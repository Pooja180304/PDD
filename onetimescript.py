import json
import csv
import time

def create_sorted_arr_and_dict():

    try:
        start = time.time()
        domain_data_array = []
        domain_data_dict = {}

        with open('static/data/top-1m.csv', newline='') as csvfile:
            reader = csv.reader(csvfile)
            for row in reader:
                domain_data_array.append(row[1]) 
                domain_data_dict[row[1]] = row[0] 


        sorted_domain_data = sorted(domain_data_array)

        with open('static/data/sorted-top1million.txt', 'w') as outfile:
            pass


        with open('static/data/sorted-top1million.txt', 'w') as outfile:
            for row in sorted_domain_data:
                outfile.write(row + '\n')


        with open('static/data/domain-rank.json', 'w') as outfile:
            pass


        with open('static/data/domain-rank.json', 'w') as outfile:
            json.dump(domain_data_dict, outfile)

        end = time.time()

        print('Script Executed Successfully.')
        print('Execution Time : ', round(end - start,2),'seconds')

    except Exception as e:
        print(f"Error: {e}")


create_sorted_arr_and_dict() 
