document.addEventListener("click", async (event) => {
  const button = event.target.closest("[data-copy-target]");
  if (!button) return;
  const target = document.getElementById(button.dataset.copyTarget);
  if (!target) return;
  await navigator.clipboard.writeText(target.textContent);
  const original = button.textContent;
  button.textContent = "Copied";
  window.setTimeout(() => { button.textContent = original; }, 1200);
});
