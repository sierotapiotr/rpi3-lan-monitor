def sqlalchemy_tuples_to_list(list_of_tuples):
    list = []
    for tuple in list_of_tuples:
        list.append(tuple[0])
    return list
