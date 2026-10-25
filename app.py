"""Assembly Annotator - web front end."""

import io
import json
import logging
import os

from flask import Flask, Response, jsonify, render_template, request

from annotator import InputTooLarge, MAX_INPUT_CHARS, analyse, __version__
from annotator import isa, registers
from annotator.examples import BY_ID, EXAMPLES

logging.basicConfig(level=logging.INFO)


def create_app(config=None):
    app = Flask(__name__)
    app.config.update(JSON_SORT_KEYS=False, MAX_CONTENT_LENGTH=2 * 1024 * 1024)
    if config:
        app.config.update(config)

    @app.route('/')
    def index():
        return render_template(
            'index.html',
            version=__version__,
            examples=[{k: v for k, v in e.items() if k != 'code'} for e in EXAMPLES],
            categories=isa.CATEGORIES,
            max_chars=MAX_INPUT_CHARS,
        )

    @app.post('/api/annotate')
    def annotate():
        data = request.get_json(silent=True) or {}
        code = data.get('code', '')
        if not isinstance(code, str) or not code.strip():
            return jsonify({'error': 'No assembly code provided.'}), 400

        arch = data.get('arch') or None
        syntax = data.get('syntax') or None
        verbosity = data.get('verbosity', 'normal')
        if arch not in (None, 'x86', 'arm', 'mips'):
            return jsonify({'error': f'Unsupported architecture: {arch}'}), 400
        if syntax not in (None, 'intel', 'att'):
            return jsonify({'error': f'Unsupported syntax: {syntax}'}), 400
        if verbosity not in ('brief', 'normal', 'verbose'):
            verbosity = 'normal'

        try:
            result = analyse(code, arch=arch, syntax=syntax, verbosity=verbosity)
        except InputTooLarge as exc:
            return jsonify({'error': str(exc)}), 413
        except Exception:
            app.logger.exception('analysis failed')
            return jsonify({'error': 'Analysis failed. Please check the input.'}), 500
        return jsonify(result)

    @app.get('/api/examples')
    def list_examples():
        return jsonify(EXAMPLES)

    @app.get('/api/examples/<example_id>')
    def get_example(example_id):
        example = BY_ID.get(example_id)
        if not example:
            return jsonify({'error': 'No such example.'}), 404
        return jsonify(example)

    @app.get('/api/instruction/<mnemonic>')
    def instruction(mnemonic):
        """Reference lookup for the instruction side panel."""
        arch = request.args.get('arch', 'x86')
        entry = isa.lookup(mnemonic, arch)
        if not entry:
            return jsonify({'error': f'`{mnemonic}` is not in the {arch} database.'}), 404
        return jsonify({'mnemonic': mnemonic.lower(), 'arch': arch, **entry})

    @app.get('/api/register/<name>')
    def register(name):
        arch = request.args.get('arch', 'x86')
        info = registers.lookup(name, arch)
        if not info:
            return jsonify({'error': f'`{name}` is not a known {arch} register.'}), 404
        role, width, parent = info
        return jsonify({'name': registers.normalise(name), 'role': role,
                        'width': width, 'parent': parent, 'arch': arch})

    @app.post('/api/export/<fmt>')
    def export(fmt):
        """Server-side export so the Markdown and HTML reports stay consistent."""
        data = request.get_json(silent=True) or {}
        code = data.get('code', '')
        if not code.strip():
            return jsonify({'error': 'No assembly code provided.'}), 400
        try:
            result = analyse(code, arch=data.get('arch') or None,
                             syntax=data.get('syntax') or None,
                             verbosity=data.get('verbosity', 'normal'))
        except InputTooLarge as exc:
            return jsonify({'error': str(exc)}), 413

        if fmt == 'json':
            body = json.dumps(result, indent=2)
            return Response(body, mimetype='application/json',
                            headers={'Content-Disposition': 'attachment; filename=analysis.json'})
        if fmt == 'md':
            return Response(_markdown_report(result), mimetype='text/markdown',
                            headers={'Content-Disposition': 'attachment; filename=analysis.md'})
        if fmt == 'txt':
            return Response(_text_report(result), mimetype='text/plain',
                            headers={'Content-Disposition': 'attachment; filename=analysis.txt'})
        return jsonify({'error': f'Unsupported export format: {fmt}'}), 400

    @app.get('/api/health')
    def health():
        return jsonify({'status': 'ok', 'version': __version__,
                        'instructions': len(isa.X86) + len(isa.ARM) + len(isa.MIPS)})

    @app.errorhandler(404)
    def not_found(_):
        return jsonify({'error': 'Not found.'}), 404

    @app.errorhandler(413)
    def too_large(_):
        return jsonify({'error': 'Request body too large.'}), 413

    return app


def _markdown_report(result) -> str:
    out = io.StringIO()
    meta, stats = result['meta'], result['stats']
    out.write('# Assembly analysis\n\n')
    out.write(f'- **Architecture:** {meta["arch"]} ({meta["syntax"]} syntax)\n')
    out.write(f'- **Instructions:** {stats["instructions"]} across {stats["lines"]} lines\n')
    out.write(f'- **Coverage:** {stats["coverage"]}% of instructions recognised\n')
    if stats['syscalls']:
        out.write(f'- **System calls:** {", ".join(stats["syscalls"])}\n')
    out.write('\n')

    if result['patterns']:
        out.write('## Detected patterns\n\n')
        for p in result['patterns']:
            lines = ', '.join(str(n) for n in p['lines'][:12])
            out.write(f'### {p["name"]}  _({p["severity"]})_\n\n{p["description"]}\n\n')
            out.write(f'Lines: {lines}\n\n')

    out.write('## Annotated listing\n\n')
    for a in result['annotations']:
        if a['kind'] == 'blank':
            continue
        out.write(f'**{a["index"]}.** `{a["raw"].strip()}`\n\n')
        out.write(f'> {a["title"]}\n\n')
        for note in a['notes']:
            out.write(f'> - {note}\n')
        if a['notes']:
            out.write('\n')
    return out.getvalue()


def _text_report(result) -> str:
    out = io.StringIO()
    meta, stats = result['meta'], result['stats']
    out.write(f'Assembly analysis - {meta["arch"]} / {meta["syntax"]} syntax\n')
    out.write(f'{stats["instructions"]} instructions, {stats["coverage"]}% recognised\n')
    out.write('=' * 78 + '\n\n')
    width = max((len(a['raw'].strip()) for a in result['annotations']), default=20)
    width = min(max(width, 16), 46)
    for a in result['annotations']:
        if a['kind'] == 'blank':
            continue
        out.write(f'{a["index"]:>4} | {a["raw"].strip():<{width}} | {a["title"]}\n')
        for note in a['notes']:
            out.write(f'{"":>4} | {"":<{width}} |   - {note}\n')
    if result['patterns']:
        out.write('\n' + '=' * 78 + '\nDETECTED PATTERNS\n\n')
        for p in result['patterns']:
            out.write(f'[{p["severity"].upper():<7}] {p["name"]}\n')
            out.write(f'          {p["description"]}\n')
            out.write(f'          Lines: {", ".join(str(n) for n in p["lines"][:12])}\n\n')
    return out.getvalue()


app = create_app()

if __name__ == '__main__':
    app.run(debug=os.environ.get('FLASK_DEBUG') == '1',
            host=os.environ.get('HOST', '127.0.0.1'),
            port=int(os.environ.get('PORT', 5000)))
