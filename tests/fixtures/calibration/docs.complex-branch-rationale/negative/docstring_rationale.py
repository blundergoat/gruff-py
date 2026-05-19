def route_payload(value):
    """Route compatibility payloads across legacy protocol branches.

    The branch table mirrors the published wire contract while the downstream
    parser migrates.
    """
    total = 0
    if value == 0:
        total += 0
    if value == 1:
        total += 1
    if value == 2:
        total += 2
    if value == 3:
        total += 3
    if value == 4:
        total += 4
    if value == 5:
        total += 5
    if value == 6:
        total += 6
    if value == 7:
        total += 7
    if value == 8:
        total += 8
    if value == 9:
        total += 9
    if value == 10:
        total += 10
    return total
