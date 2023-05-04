def join_values(l):
    return " ".join(l)


def split_banner(b):
    headings = {'test': 'test'}
    banner = b.split()
    heading_word = ""
    value = ""
    for i in range(len(banner)):

        word = banner[i]
        last_word = banner[-1]
        if word.endswith(':') and word is not last_word:
            heading_word = word.strip(':')
            value = banner[i + 1]
            headings[heading_word] = [value]
        elif word is not value:
            try:
                headings[heading_word].append(word)
            except KeyError:
                continue

    try:
        product = headings['product']
        full_product = join_values(product)
    except KeyError:
        full_product = 'Unknown'

    try:
        version = headings['version']
        full_version = join_values(version)
    except KeyError:
        full_version = 'Unknown'
    return full_product, full_version