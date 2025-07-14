const analyzeBtn = document.getElementById('analyzeBtn');
const codeInput = document.getElementById('codeInput');
const annotationsPre = document.getElementById('annotations');
const annotationsCode = annotationsPre.querySelector('code');
const patternList = document.getElementById('patternList');

analyzeBtn.addEventListener('click', () => {
  const code = codeInput.value;
  analyzeBtn.disabled = true;
  analyzeBtn.textContent = 'Analyzing...';

  fetch('/annotate', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({code})
  })
  .then(res => res.json())
  .then(data => {
    if (data.error) {
      annotationsCode.textContent = `Error: ${data.error}`;
      patternList.innerHTML = '';
    } else {
      const annotations = data.annotations.map((
        item, index) => `${index + 1} | ${item.code} => ${item.explanation}`
      ).join('\n');
      annotationsCode.textContent = annotations;

      patternList.innerHTML = '';
      data.patterns.forEach(pattern => {
        const chip = document.createElement('div');
        chip.textContent = pattern;
        patternList.appendChild(chip);
      });

      // Trigger Prism to highlight the updated code block
      Prism.highlightElement(annotationsCode);
    }
  })
  .catch(err => {
    annotationsCode.textContent = `Error: ${err.message}`;
    patternList.innerHTML = '';
  })
  .finally(() => {
    analyzeBtn.disabled = false;
    analyzeBtn.textContent = 'Analyze';
  });
});

document.getElementById('clearBtn').addEventListener('click', () => {
  codeInput.value = '';
  annotationsCode.textContent = '';
  patternList.innerHTML = '';
});

document.getElementById('exampleBtn').addEventListener('click', () => {
  codeInput.value = `
push ebp
mov ebp, esp
sub esp, 0x20
cmp eax, 0x1337
jne AccessDenied
call printf
mov eax, 0
pop ebp
ret
`;
});

document.getElementById('saveBtn').addEventListener('click', () => {
  const code = codeInput.value;
  if (code.trim()) {
    localStorage.setItem('savedAssemblyCode', code);
    alert('Code saved locally.');
  } else {
    alert('No code to save.');
  }
});

document.getElementById('loadBtn').addEventListener('click', () => {
  const savedCode = localStorage.getItem('savedAssemblyCode');
  if (savedCode) {
    codeInput.value = savedCode;
    alert('Code loaded from local storage.');
  } else {
    alert('No saved code found.');
  }
});

document.getElementById('exportTextBtn').addEventListener('click', () => {
  if (!annotationsCode.textContent.trim()) {
    alert('No annotations to export.');
    return;
  }
  const blob = new Blob([annotationsCode.textContent], {type: 'text/plain'});
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = 'annotations.txt';
  a.click();
  URL.revokeObjectURL(url);
});

document.getElementById('exportJsonBtn').addEventListener('click', () => {
  if (!annotationsCode.textContent.trim()) {
    alert('No annotations to export.');
    return;
  }
  // Prepare JSON data with annotations and patterns
  const annotationsLines = annotationsCode.textContent.split('\n').map(line => {
    const parts = line.split(' => ');
    return {line: parts[0], explanation: parts[1]};
  });
  const data = {
    annotations: annotationsLines,
    patterns: Array.from(patternList.children).map(div => div.textContent)
  };
  const blob = new Blob([JSON.stringify(data, null, 2)], {type: 'application/json'});
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = 'annotations.json';
  a.click();
  URL.revokeObjectURL(url);
});

// Keyboard shortcuts for accessibility and convenience
document.addEventListener('keydown', (e) => {
  if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
    e.preventDefault();
    analyzeBtn.click();
  }
  if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 's') {
    e.preventDefault();
    document.getElementById('saveBtn').click();
  }
  if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'l') {
    e.preventDefault();
    document.getElementById('loadBtn').click();
  }
});
