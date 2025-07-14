from flask import Flask, render_template, request, jsonify
import re

app = Flask(__name__)

# Expanded explanations dictionary with more detailed descriptions
EXPLANATIONS = {
    'mov': 'Copy data from source operand to destination operand',
    'add': 'Add source operand to destination operand and store result',
    'sub': 'Subtract source operand from destination operand and store result',
    'push': 'Push operand onto the stack',
    'pop': 'Pop value from the stack into operand',
    'call': 'Call procedure at operand address',
    'cmp': 'Compare two operands by subtracting and setting flags',
    'jne': 'Jump to target if zero flag is not set (not equal)',
    'je': 'Jump to target if zero flag is set (equal)',
    'ret': 'Return from procedure',
    'jmp': 'Unconditional jump to target address',
    'imul': 'Signed multiply',
    'idiv': 'Signed divide',
    'lea': 'Load effective address',
    'nop': 'No operation',
    'inc': 'Increment operand by 1',
    'dec': 'Decrement operand by 1',
    'and': 'Bitwise AND',
    'or': 'Bitwise OR',
    'xor': 'Bitwise XOR',
    'shl': 'Shift bits left',
    'shr': 'Shift bits right'
}

# Expanded patterns to detect with regex support
PATTERNS = [
    {
        'name': 'Function Prologue',
        'sequence': ['push ebp', 'mov ebp, esp']
    },
    {
        'name': 'Function Epilogue',
        'sequence': ['pop ebp', 'ret']
    },
    {
        'name': 'Password Check',
        'keywords': ['cmp', 'jne', 'je']
    },
    {
        'name': 'Arithmetic Operation',
        'keywords': ['add', 'sub', 'imul', 'idiv']
    },
    {
        'name': 'Stack Frame Setup',
        'sequence': ['push ebp', 'mov ebp, esp', 'sub esp']
    },
    {
        'name': 'Function Call Sequence',
        'sequence': ['call', 'add esp']
    },
    {
        'name': 'Loop Start',
        'keywords': ['jmp', 'cmp', 'jne']
    },
    {
        'name': 'Conditional Jump',
        'keywords': ['je', 'jne', 'jg', 'jl', 'jge', 'jle']
    },
    {
        'name': 'NOP Sled',
        'regex': r'^(nop\s*){3,}$'
    },
    {
        'name': 'Repeated Pushes',
        'regex': r'^(push\s+\w+\s*){3,}$'
    }
]

def match_regex_pattern(pattern, lines):
    regex = re.compile(pattern, re.IGNORECASE)
    for line in lines:
        if regex.match(line):
            return True
    return False

@app.route('/')
def index():
    return render_template('index.html', app_name="Assembly Insight")

@app.route('/annotate', methods=['POST'])
def annotate():
    try:
        data = request.get_json()
        code = data.get('code', '')
        if not code.strip():
            return jsonify({'error': 'No assembly code provided'}), 400

        max_input_size = 10000
        if len(code) > max_input_size:
            return jsonify({'error': f'Input too large. Maximum allowed characters: {max_input_size}'}), 400

        lines = code.strip().split('\n')
        annotations = []
        normalized = [
            l.strip().lower()
            for l in lines
            if l.strip() and not l.strip().startswith(';')
        ]

        for line in lines:
            clean = line.strip()
            if not clean or clean.startswith(';'):
                continue

            tokens = clean.lower().split()
            if not tokens:
                continue

            instr = tokens[0]
            explanation = EXPLANATIONS.get(instr, 'Unknown instruction')
            annotations.append({
                'code': line,
                'explanation': explanation
            })

        detected_patterns = set()
        for pattern in PATTERNS:
            if 'sequence' in pattern:
                if all(p in normalized for p in pattern['sequence']):
                    detected_patterns.add(pattern['name'])
            elif 'keywords' in pattern:
                if any(any(k in line for k in pattern['keywords']) for line in normalized):
                    detected_patterns.add(pattern['name'])
            elif 'regex' in pattern:
                if match_regex_pattern(pattern['regex'], normalized):
                    detected_patterns.add(pattern['name'])

        return jsonify({
            'annotations': annotations,
            'patterns': list(detected_patterns)
        })
    except Exception as e:
        return jsonify({'error': f'Error processing code: {str(e)}'}), 500

if __name__ == '__main__':
    app.run(debug=True)
