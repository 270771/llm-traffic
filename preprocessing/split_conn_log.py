# Takes a Zeek conn.log file, separates its header and connection data, and splits the data
# into multiple numbered log files of a specified size, each retaining the original headers

import os

# Function to split a Zeek conn.log file into smaller files with a fixed number of data records each
def split_conn_log(file_path, instances_per_file=108, output_dir="split_logs"):
    # Check if the provided file path exists
    if not os.path.isfile(file_path):
        print(f"Error: File '{file_path}' does not exist.")
        return

    # Create the output directory if it doesn't already exist
    os.makedirs(output_dir, exist_ok=True)

    # Read all lines from the conn.log file
    with open(file_path, 'r') as f:
        lines = f.readlines()

    # Separate header lines (starting with "#") from actual connection data lines
    header_lines = [line for line in lines if line.startswith("#")]
    data_lines = [line for line in lines if not line.startswith("#") and line.strip() != ""]

    # Calculate how many chunks are needed based on the desired number of instances per file
    total_chunks = (len(data_lines) + instances_per_file - 1) // instances_per_file

    print(f"Splitting {len(data_lines)} records into {total_chunks} files...")

    # Loop through and create each chunk file
    for i in range(total_chunks):
        # Slice the data into chunks
        chunk_lines = data_lines[i * instances_per_file:(i + 1) * instances_per_file]

        # Create a file name like conn_log_part_1.log, conn_log_part_2.log, etc.
        output_file = os.path.join(output_dir, f"conn_log_part_{i + 1}.log")

        # Write headers and current chunk of data lines to the new file
        with open(output_file, 'w') as out_f:
            out_f.writelines(header_lines)  # Include Zeek metadata headers for each split file
            out_f.writelines(chunk_lines)

        # Notify the user of the new file created
        print(f"Created {output_file} with {len(chunk_lines)} Zeek records.")

# Run this script
if __name__ == "__main__":
    # Prompt the user to enter the path to the conn.log file to split
    input_path = input("Enter path to Zeek conn.log file: ").strip()
    split_conn_log(input_path)
