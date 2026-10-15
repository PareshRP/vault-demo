(() => {
  const container = document.getElementById('selected-files');
  if (!container) return;
  const inputs = Array.from(document.querySelectorAll('input[type="file"][name="files"]'));
  const render = () => {
    const selected = inputs.flatMap(input => Array.from(input.files || []).map(file => ({
      name: file.webkitRelativePath || file.name,
      size: file.size
    })));
    container.replaceChildren();
    if (!selected.length) {
      const strong = document.createElement('strong');
      strong.textContent = 'No files selected yet';
      const note = document.createElement('span');
      note.textContent = 'Selected file names will appear here before preview.';
      container.append(strong, note);
      return;
    }
    const heading = document.createElement('strong');
    heading.textContent = `${selected.length} file${selected.length === 1 ? '' : 's'} selected`;
    container.append(heading);
    const list = document.createElement('ul');
    selected.forEach(file => {
      const item = document.createElement('li');
      const name = document.createElement('span');
      name.textContent = file.name;
      const size = document.createElement('small');
      size.textContent = `${Math.ceil(file.size / 1024)} KB`;
      item.append(name, size);
      list.append(item);
    });
    container.append(list);
  };
  inputs.forEach(input => input.addEventListener('change', render));
})();
