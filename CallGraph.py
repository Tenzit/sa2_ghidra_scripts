#@author Tenzit
#@category SA2
#@keybinding 
#@menupath 
#@toolbar 
#@runtime PyGhidra

# For VS Code type checking stuff
try:
    from typing import TYPE_CHECKING
except:
    TYPE_CHECKING = False

if TYPE_CHECKING:
    from ghidra.ghidra_builtins import *

from typing import cast

from ghidra.program.model.util import AcyclicCallGraphBuilder
from ghidra.app.services import GraphDisplayBroker
from ghidra.util.graph import *
from ghidra.service.graph import AttributedGraph
from ghidra.graph import CallGraphType, ProgramGraphDisplayOptions, DefaultGEdge, GraphAlgorithms
from ghidra.graph.jung import JungDirectedGraph
from ghidra.program.model.listing import Function

builder = AcyclicCallGraphBuilder(currentProgram, True)

depGraph = builder.getDependencyGraph(monitor)

jungGraph = JungDirectedGraph()

while depGraph.hasUnVisitedIndependentValues():
    for val in depGraph.getUnvisitedIndependentValues():
        valFn = getFunctionAt(val)
        jungGraph.addVertex(valFn)
        deps = depGraph.getDependentValues(val)
        for dep in deps:
            depFn = getFunctionAt(dep)
            jungGraph.addVertex(depFn)
            jungGraph.addEdge(DefaultGEdge(depFn, valFn))
        depGraph.remove(val)

noLibCtorGraph = jungGraph.copy()

libraryTag = currentProgram.getFunctionManager().getFunctionTagManager().getFunctionTag("LIBRARY")
ctorTag = currentProgram.getFunctionManager().getFunctionTagManager().getFunctionTag("CONSTRUCTOR")
vert: Function
removelist = []
ctorList = []
for vert in noLibCtorGraph.getVertices():
    if vert.getTags().contains(libraryTag):
        removelist.append(vert)
    if vert.getTags().contains(ctorTag):
        ctorList.append(vert)

noLibCtorGraph.removeVertices(removelist)
noLibGraph = noLibCtorGraph.copy()
noLibCtorGraph.removeVertices(ctorList)

tool = state.getTool()
service: GraphDisplayBroker = cast(GraphDisplayBroker,tool.getService(GraphDisplayBroker))

disp = service.getDefaultGraphDisplay(False, monitor)

graphOpts = ProgramGraphDisplayOptions(CallGraphType(), tool)
graphOpts.setMaxNodeCount(50000)

#disp.setGraph(jungGraph, graphOpts, "Acyclic graph", False, monitor)

#print(jungGraph)

currFn = getFunctionContaining(currentAddress)

descendants = GraphAlgorithms.getDescendants(noLibCtorGraph, [currFn])
ctorDescs = GraphAlgorithms.getDescendants(noLibGraph, [currFn])

print(f"Num descendants from {currFn}: {len(descendants)}")

descendants.add(currFn)

subTree = GraphAlgorithms.createSubGraph(noLibCtorGraph, descendants)

ctorTrees = []
for desc in ctorDescs:
    if desc not in ctorList:
        continue
    ctDescs = GraphAlgorithms.getDescendants(noLibGraph, [desc])
    ctDescs.add(desc)
    ctorSubTree = GraphAlgorithms.createSubGraph(noLibGraph, ctDescs)
    ctorTrees.append(ctorSubTree)

attrGraph = AttributedGraph(f"{currFn} subtree", CallGraphType())

vert_map = {}
for vert in subTree.getVertices():
    av = attrGraph.addVertex(vert.getName())
    vert_map[vert] = av

for ctorTree in ctorTrees:
    for vert in ctorTree.getVertices():
        if vert not in vert_map:
            av = attrGraph.addVertex(vert.getName())
            vert_map[vert] = av

for edge in subTree.getEdges():
    eStart = edge.getStart()
    eEnd = edge.getEnd()
    attrGraph.addEdge(vert_map[eStart], vert_map[eEnd])

for ctorTree in ctorTrees:
    for edge in ctorTree.getEdges():
        eStart = edge.getStart()
        eEnd = edge.getEnd()
        attrGraph.addEdge(vert_map[eStart], vert_map[eEnd])

print(f"Num verts: {attrGraph.getVertexCount()}; num edges: {attrGraph.getEdgeCount()}")
disp.setGraph(attrGraph, graphOpts, f"Acyclic graph @ {currFn}", False, monitor)