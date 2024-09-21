# Function to extract the first 15,000 lines from a file and save to a new file
def extract_first_15000(input_file, output_file):
    with open(input_file, 'r') as file:
        # Read the first 15,000 lines
        lines = [next(file) for _ in range(70000)]
    
    # Write the extracted lines to the output file
    with open(output_file, 'w') as output_file:
        output_file.writelines(lines)
    print(f"First 70,000 lines have been written to '{output_file.name}'")

# Extract the first 15,000 lines from both train.txt and test.txt
extract_first_15000('Train.txt', 'Train_sample.txt')
extract_first_15000('Test.txt', 'Test_sample.txt')