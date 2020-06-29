import networkx as nx


graph = nx.DiGraph()
graph.add_node('n1')
graph.add_node('n2')
graph.add_edge('n1', 'n2')

print(graph.edges())
print(graph.nodes())


    
