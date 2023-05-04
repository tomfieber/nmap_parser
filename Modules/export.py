import os

def exportCsv(dict):
    if not os.path.exists("./output/"):
        os.mkdir("./output/")
    with open('./output/listening-services.csv', 'w') as csvfile:
        csvfile.write(f"Port, Listening Services\n")
        for key in dict.keys():
            csvfile.write(f"{key} - {dict[key]['protocol']}, {dict[key]['count']}\n")