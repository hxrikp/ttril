def transform_keys(key_list):
    transformed_list = []
    for key in key_list:
        # Data Cleaning : Replace certain characters with spaces
        key = key.replace('.', ' ')
        key = key.replace('_', ' ')
        key = key.replace('-', ' ')

        # Create a new string with appropriate spacing for words
        new_string = ""
        new_string += key[0]

        for i in range(1, len(key)):
            # Insert a space before uppercase letters preceded by lowercase letters (except for spaces)
            if key[i].isupper() and key[i - 1].islower() and key[i - 1] != ' ':
                new_string += ' '
                new_string += key[i]
            else:
                new_string += key[i]

        # Convert the transformed key to lowercase and add it to the transformed list
        transformed_list.append(new_string.lower())

    return transformed_list


def find_list_with_string(list_of_lists, search_string):
    result = []
    for sublist in list_of_lists:
        # Check if the search string is present in the current sublist
        if search_string in sublist:
            result.append(sublist)  # Append the sublist to the result list if the search string is found
    return result


def add_new_words(existing_words, new_words):
    unique_words = set(existing_words)  # Convert existing_words to a set to eliminate duplicates
    for word in new_words:
        if word not in unique_words:
            unique_words.add(word)  # Add word to the set if it is not present
    return list(unique_words)  # Convert the set back to a list and return it
