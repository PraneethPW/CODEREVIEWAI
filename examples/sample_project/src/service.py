import ast

def parse_preferences(raw_value):
    return ast.literal_eval(raw_value)
