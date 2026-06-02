#!/usr/bin/env python3

# Build script to assemble the source files into a single
# HTML output file (index.html).

import re

# Replace {{filename}} within source to include the contents
# of the named files.
def expand_template(source):
  def expand_include(match):
    filename = match.group(1)
    with open(filename, 'r') as included_file:
      return included_file.read().strip()
  pattern = r'\{\{([^}]+)\}\}'
  return re.sub(pattern, expand_include, source)

def build(input_filename, output_filename):
  with open(input_filename, 'r') as input_file:
    source = input_file.read()
  output = expand_template(source)
  with open(output_filename, 'w') as output_file:
    output_file.write(output)


if __name__ == "__main__":
  output_filename = "../ajbcrypt.html"
  build("source.html", output_filename)
  print("Wrote", output_filename)

