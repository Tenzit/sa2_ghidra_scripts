//Create multiple libraries in a single FID database
//@category SA2
import java.io.*;
import java.util.*;
import java.util.Map.Entry;

import generic.hash.FNV1a64MessageDigest;
import generic.hash.MessageDigest;
import ghidra.app.script.GhidraScript;
import ghidra.feature.fid.db.*;
import ghidra.feature.fid.hash.FidHashQuad;
import ghidra.feature.fid.service.*;
import ghidra.feature.fid.service.FidPopulateResult.Disposition;
import ghidra.framework.model.*;
import ghidra.program.database.ProgramContentHandler;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

public class AddToFID extends GhidraScript {

	private FidService service;
	private FidDB fidDb = null;
	private FidFile fidFile = null;
	private DomainFolder rootFolder = null;
	private int totalLibraries = 0;
	private boolean isCancelled = false;

	private String[] pathelement;
	private String currentLibraryName;
	private String currentLibraryVersion;
	private String currentLibraryVariant;

	private LanguageID languageID = null;

	private MyFidPopulateResultReporter reporter = null;

	private static final int MASTER_DEPTH = 3;

	class MyFidPopulateResultReporter implements FidPopulateResultReporter {
		@Override
		public void report(FidPopulateResult result) {
			if (result == null) {
				return;
			}
			LibraryRecord libraryRecord = result.getLibraryRecord();
			String libraryFamilyName = libraryRecord.getLibraryFamilyName();
			String libraryVersion = libraryRecord.getLibraryVersion();
			String libraryVariant = libraryRecord.getLibraryVariant();
			println(libraryFamilyName + ':' + libraryVersion + ':' + libraryVariant);

			println(result.getTotalAttempted() + " total functions visited");
			println(result.getTotalAdded() + " total functions added");
			println(result.getTotalExcluded() + " total functions excluded");
			println("Breakdown of exclusions:");
			for (Entry<Disposition, Integer> entry : result.getFailures().entrySet()) {
				if (entry.getKey() != Disposition.INCLUDED) {
					println("    " + entry.getKey() + ": " + entry.getValue());
				}
			}
			println("List of unresolved symbols:");
			TreeSet<String> symbols = new TreeSet<>();
			for (Location location : result.getUnresolvedSymbols()) {
				symbols.add(location.getFunctionName());
			}
			for (String symbol : symbols) {
				println("    " + symbol);
			}
		}

	}

	private void hashFunction(Program program, ArrayList<Long> hashList)
			throws MemoryAccessException, CancelledException {
		FunctionManager functionManager = program.getFunctionManager();
		FunctionIterator functions = functionManager.getFunctions(true);
		while (functions.hasNext()) {
			monitor.checkCancelled();
			Function func = functions.next();
			FidHashQuad hashFunction = service.hashFunction(func);
			if (hashFunction == null) {
				continue; // No body
			}
			MessageDigest digest = new FNV1a64MessageDigest();
			digest.update(func.getName().getBytes(), TaskMonitor.DUMMY);
			digest.update(hashFunction.getFullHash());
			hashList.add(digest.digestLong());
		}
	}

	private void hashListProgram(DomainFile domainFile, ArrayList<Long> hashList)
			throws VersionException, CancelledException, IOException, MemoryAccessException {
		DomainObject domainObject = null;
		try {
			domainObject = domainFile.getDomainObject(this, false, true, TaskMonitor.DUMMY);
			if (!(domainObject instanceof Program)) {
				return;
			}
			Program program = (Program) domainObject;
			hashFunction(program, hashList);
		}
		finally {
			if (domainObject != null) {
				domainObject.release(this);
			}
		}

	}

	private long calculateFinalHash(ArrayList<Long> hashList) throws CancelledException {
		MessageDigest digest = new FNV1a64MessageDigest();
		Collections.sort(hashList);
		for (int i = 0; i < hashList.size(); ++i) {
			monitor.checkCancelled();
			digest.update(hashList.get(i));
		}
		return digest.digestLong();
	}

	private void createLibraryNames(DomainFile domainFile) {
		// path should look like : compiler, project, version, options
		currentLibraryName = domainFile.getName().split("[.]")[0];
		currentLibraryVersion = "Katana R11b";
		currentLibraryVariant = "Gnu";
	}

	private void countLibraries(int depth, DomainFolder fold) {
		if (depth == 0) {
			totalLibraries += 1;
			return;
		}
		depth -= 1;
		DomainFolder[] subfold = fold.getFolders();
		for (DomainFolder element : subfold) {
			countLibraries(depth, element);
		}
	}

	/**
	 * Finds all domain objects that are program files under a domain folder.
     * Assumes there are no sub-folders inside the input folder
	 * @param programs the "return" value; found programs are placed in this collection
	 * @param myFolder the domain folder to search
	 * @throws CancelledException if the user cancels
	 */
	protected void findPrograms(ArrayList<DomainFile> programs, DomainFolder myFolder)
			throws CancelledException {
		if (myFolder == null) {
			return;
		}
		DomainFile[] files = myFolder.getFiles();
		for (DomainFile domainFile : files) {
			monitor.checkCancelled();
			// Do not follow folder-links or consider program links.  Using content type
			// to filter is best way to control this.  If program links should be considered
			// "Program.class.isAssignableFrom(domainFile.getDomainObjectClass())"
			// should be used.
			if (domainFile.getContentType().equals(ProgramContentHandler.PROGRAM_CONTENT_TYPE)) {
				programs.add(domainFile);
			}
		}
	}

	private void populateLibrary(DomainFolder folder) {
		ArrayList<DomainFile> programs = new ArrayList<>();
		try {
			findPrograms(programs, folder);

            for (DomainFile domainFile : programs) {
                createLibraryNames(domainFile);
			    FidPopulateResult result = service.createNewLibraryFromPrograms(fidDb,
				    currentLibraryName, currentLibraryVersion, currentLibraryVariant, List.of(domainFile), null,
				    languageID, null, null, TaskMonitor.DUMMY);
			    reporter.report(result);
            }
		}
		catch (CancelledException e) {
			isCancelled = true;
		}
		catch (MemoryAccessException e) {
			Msg.showError(this, null, "Unexpected memory access exception",
				"Please notify the Ghidra team:", e);
		}
		catch (VersionException e) {
			Msg.showError(this, null, "Version Exception",
				"One of the programs in your domain folder cannot be upgraded: " + e.getMessage());
		}
		catch (IllegalStateException e) {
			Msg.showError(this, null, "Illegal State Exception",
				"Unknown error: " + e.getMessage());
		}
		catch (IOException e) {
			Msg.showError(this, null, "FidDb IOException", "Please notify the Ghidra team:", e);
		}
	}

	@Override
	protected void run() throws Exception {
		pathelement = new String[MASTER_DEPTH + 1];
		service = new FidService();

		List<FidFile> nonInstallationFidFiles = FidFileManager.getInstance().getUserAddedFiles();
		if (nonInstallationFidFiles.isEmpty()) {
			throw new FileNotFoundException("Could not find any fidb files that can be populated");
		}
		fidFile = askChoice("Choose destination FidDB",
			"Please choose the destination FidDB for population", nonInstallationFidFiles,
			nonInstallationFidFiles.get(0));

		rootFolder =
			askProjectFolder("Select root folder containing all libraries");

		String lang = askString("Enter LanguageID To Process", "Language ID: ");
		languageID = new LanguageID(lang);

		reporter = new MyFidPopulateResultReporter();
		fidDb = fidFile.getFidDB(true);

		countLibraries(MASTER_DEPTH, rootFolder);
		monitor.initialize(totalLibraries);
		try {
            populateLibrary(rootFolder);
			fidDb.saveDatabase("Saving", monitor);
		}
		finally {
			fidDb.close();
		}
	}

}
