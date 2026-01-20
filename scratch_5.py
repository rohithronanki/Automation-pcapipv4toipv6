import re


def convert_special_chars_to_hex_grouped(input_string):
    """
    Converts special characters in a string to their hexadecimal representation,
    grouped within '|' delimiters for consecutive special characters,
    with hex values separated by spaces. Single special characters are also
    enclosed.

    Args:
        input_string (str): The input string.

    Returns:
        str: The string with special characters converted to hex format.
    """

    def replace_match(match):
        # Get the matched sequence of special characters
        matched_sequence = match.group(0)

        # Convert each character in the sequence to its hex representation
        hex_values = [f"{ord(char):02x}" for char in matched_sequence]

        # Join the hex values with spaces and enclose them with '|'
        return f"|{' '.join(hex_values)}|"

    # Use a regular expression to find sequences of one or more special characters
    # A special character is anything that is not alphanumeric or a whitespace
    # The regex [^a-zA-Z0-9\s]+ matches any sequence of non-alphanumeric, non-whitespace chars.
    output_string = re.sub(r'[^a-zA-Z0-9\s]+', replace_match, input_string)
    return output_string


# --- Example Usage ---
input_strings = [
    "stvgzby63.top/1.php?s=63e95be1-92e0-45c1-a928-65d63b17cd1c",
"rlxwzlils072stb.top/1.php?s=04e1ab2b-3f93-46fa-9aed-c3a2a3f126c9","madjbmlnajhefbg.top/c1fs9q6l4dhtr.php?id=DESKTOP-Y45BDH2&key=36571885104&s=63e95be1-92e0-45c1-a928-65d63b17cd1c","/st2?s=04e1ab2b-3f93-46fa-9aed-c3a2a3f126c9&id=DESKTOP-Y45BDH2&key=33646671108","media.cloud341.xyz/file.zip?c=AIY4xWhYdAUAXFgCAE9NFwASAAAAAAD6&s=357464","media.cloud3413.click/ByJusticeorMercy-v14-pc.zip.zip?c=AF_CwWgCeAUAXFgCAE5PFwASAAAAAAD8&s=358402","media.cloud9342.homes/Hollow-Knight-Silksong-SteamRIP.com.rar.zip?c=AHfS3GgCeAUACocCAEtaFwASAAAAAABS&s=358402","media.cloud9342.quest/Download.zip?c=AIbc3GjrdAUAXFgCAE1YFwASAAAAAADI&s=357611","media.cloud93421.click/Download_DreamWorks_Madagascar_(USA)_(v3.01).zip?c=AIb9yWiKcwUAn4ICAElRFwASAAAAAABe&s=357258","media.cloud934221.baby/COMO_INSTALAR.zip?c=ALfN3GiKcwUA_YUCAE1YFwASAAAAAAAm&s=357258"
]

# Create an empty array to store the outputs
output_strings = []

# Iterate through the input array and append the results to the output array
for input_str in input_strings:
    output_str = convert_special_chars_to_hex_grouped(input_str)
    output_strings.append(output_str)

# Print the final arrays
print(f"Input array: {input_strings}")
print(f"Output array: {output_strings}")
# print("--- Test Case 1: Consecutive identical special characters ---")
# input_str1 = "desk-app-now.com/lander/domain/EndifAlready.exe"
# output_str1 = convert_special_chars_to_hex_grouped(input_str1)
# print(f"Input: '{input_str1}'")
# print(f"Output: '{output_str1}'")
# # Expected Output: 'Special |24 24 24| characters |26 26 26| here|2e|'
#
# print("\n--- Test Case 2: Mixed consecutive special characters ---")
# input_str2 = "Hello!@#world."
# output_str2 = convert_special_chars_to_hex_grouped(input_str2)
# print(f"Input: '{input_str2}'")
# print(f"Output: '{output_str2}'")
# # Expected Output: 'Hello|21 40 23|world|2e|'
#
# print("\n--- Test Case 3: Single special characters ---")
# input_str3 = "Test, String. Here!"
# output_str3 = convert_special_chars_to_hex_grouped(input_str3)
# print(f"Input: '{input_str3}'")
# print(f"Output: '{output_str3}'")
# # Expected Output: 'Test|2c| String|2e| Here|21|'
#
# print("\n--- Test Case 4: No special characters ---")
# input_str4 = "NoSpecialCharsHere123"
# output_str4 = convert_special_chars_to_hex_grouped(input_str4)
# print(f"Input: '{input_str4}'")
# print(f"Output: '{output_str4}'")
# # Expected Output: 'NoSpecialCharsHere123'
#
# print("\n--- Test Case 5: All special characters ---")
# input_str5 = "!@#$%^&*()"
# output_str5 = convert_special_chars_to_hex_grouped(input_str5)
# print(f"Input: '{input_str5}'")
# print(f"Output: '{output_str5}'")
# # Expected Output: '|21 40 23 24 25 5e 26 2a 28 29|'
#
# print("\n--- Test Case 6: Special characters at the beginning/end ---")
# input_str6 = "!!!Start and End@@@"
# output_str6 = convert_special_chars_to_hex_grouped(input_str6)
# print(f"Input: '{input_str6}'")
# print(f"Output: '{output_str6}'")
# # Expected Output: '|21 21 21|Start and End|40 40 40|'