'use strict';
// Progressive enhancement: the textarea remains the submitted, server-validated source.
document.querySelectorAll('.ocimd-policy').forEach((box) => {
  const source = box.querySelector('textarea');
  const kind = box.dataset.kind;
  const editor = document.createElement('div');
  const input = document.createElement('input');
  input.type = 'text'; input.id = source.id + '-entry';
  input.setAttribute('aria-label', box.querySelector('label').textContent + ': add entries');
  input.placeholder = kind === 'email' ? 'person@company.com' : 'company.com';
  const add = document.createElement('button'); add.type = 'button'; add.textContent = 'Add'; add.className = 'button';
  const feedback = document.createElement('p'); feedback.id = source.id + '-feedback'; feedback.setAttribute('role', 'status'); feedback.setAttribute('aria-live', 'polite');
  input.setAttribute('aria-describedby', feedback.id);
  const chips = document.createElement('ul'); chips.className = 'ocimd-chips';
  const domain = (s) => s.length <= 253 && /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(s) && !/(^|\.)(localhost|local|test|invalid|example|internal|lan|home|localdomain)$/.test(s) && !s.endsWith('.home.arpa');
  const valid = (s) => kind === 'domain' ? domain(s) : s.length <= 254 && /^[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9.-]+$/.test(s) && domain(s.split('@')[1]);
  let entries = source.value.split(/[,;\s]+/).filter(Boolean);
  const draw = () => {
    source.value = entries.join('\n'); chips.replaceChildren();
    entries.forEach((entry) => {
      const li = document.createElement('li'); const remove = document.createElement('button');
      remove.type = 'button'; remove.textContent = '×'; remove.setAttribute('aria-label', 'Remove ' + entry);
      remove.addEventListener('click', () => { entries = entries.filter((v) => v !== entry); draw(); input.focus(); });
      li.append(document.createTextNode(entry + ' '), remove); chips.append(li);
    });
  };
  const accept = () => {
    let added = 0, duplicate = 0; const invalid = [];
    input.value.trim().split(/[,;\s]+/).filter(Boolean).forEach((raw) => {
      const entry = raw.toLowerCase();
      if (!valid(entry) || entries.length >= 200 && !entries.includes(entry)) invalid.push(raw);
      else if (entries.includes(entry)) duplicate++;
      else { entries.push(entry); added++; }
    });
    draw(); input.value = invalid.join(' '); input.setAttribute('aria-invalid', invalid.length ? 'true' : 'false');
    input.setCustomValidity(invalid.length ? 'Correct or remove invalid entries before saving.' : '');
    feedback.textContent = `${added} added; ${duplicate} duplicates skipped; ${invalid.length} invalid or over-limit entries left to correct. Server validation also runs when saving.`;
  };
  add.addEventListener('click', accept);
  input.addEventListener('keydown', (e) => { if (e.key === 'Enter') { e.preventDefault(); accept(); } });
  input.addEventListener('paste', () => setTimeout(accept, 0));
  input.addEventListener('input', () => input.setCustomValidity(''));
  source.form.addEventListener('submit', (e) => { if (input.value.trim()) accept(); if (!input.checkValidity()) { e.preventDefault(); input.reportValidity(); } });
  source.hidden = true; box.querySelector('label').htmlFor = input.id;
  editor.append(input, document.createTextNode(' '), add, feedback, chips); box.insertBefore(editor, source); draw();
});
const allowAny = document.querySelector('input[name="unrestricted"]');
if (allowAny) {
  const syncAllowLists = () => {
    document.querySelectorAll('.ocimd-policy[data-policy="allow"]').forEach((box) => {
      box.hidden = allowAny.checked;
      box.querySelectorAll('input, textarea, button').forEach((control) => { control.disabled = allowAny.checked; });
    });
  };
  allowAny.addEventListener('change', syncAllowLists);
  syncAllowLists();
}
const accessTest = document.querySelector('#ocimd-access-test-form');
const accessResult = document.querySelector('#ocimd-policy-result');
if (accessTest && accessResult) {
  accessTest.querySelectorAll('input[name="test_email"], input[name="verified"]').forEach((input) => {
    input.addEventListener('input', () => { accessResult.hidden = true; });
    input.addEventListener('change', () => { accessResult.hidden = true; });
  });
}
