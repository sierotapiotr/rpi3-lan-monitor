def sqlalchemyTuplesToList(list_of_tuples):
    list = []
    for tuple in list_of_tuples:
        list.append(tuple[0])
    return list