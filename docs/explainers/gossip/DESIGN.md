# Gossip relay trainer — Figure

Concept: eight latching relay modules on a circuit trainer retain a message; moving contacts on etched traces show copies travelling to neighbours, never from a central distributor.

Model: synchronous push gossip. Each online informed peer samples up to fanout distinct online neighbours uniformly without replacement, every round. Newly informed peers first send in the following round. Receivers keep one copy by message ID; other arrivals are duplicates. Lossless links, no TTL, unlimited retries, stable stored memory while offline. Seeded PRNG for repeatable reset. This is educational, not meshmsg protocol documentation. Two four-peer loops share one bridge. Opening that bridge partitions the graph.

Parts before geometry (81 solids):
- Base: four rectangular rubber feet, lower chassis, gasket, upper PCB, two side retaining rails, engraved label plate (10).
- Eight peer assemblies: socket, ceramic housing, lid flange, window bezel, window backing, memory latch, switch recess, switch paddle (64).
- Bridge disconnect: two terminal pads, recessed switch housing, sliding contact (4).
- Three chassis retaining blocks (3).
- Surface details: corner screw heads, closed vent slots, socket contact pads, lid seams, window rims, switch grip grooves; nine non-crossing etched traces ending on terminal pads.

World: x/y on circuit board, z up. Four columns, two rows. Camera azimuth 60°, elevation 38°. Static solids use the anatomy kit. No pipes, cables or turned bodies: connections are planar PCB traces. Module assemblies sorted by depth; traces and travelling highlights beneath module bodies, each module stacked bottom-to-top.

Interaction: Play/pause, Step round, Reset, fanout 1–3, source selection, bridge switch, keyboard-accessible peer toggles. Auto demonstration stops on interaction. Reduced motion starts paused and steps instantly. Offscreen/hidden animation pauses. Standalone dark/light HTML, no external runtime requests.
