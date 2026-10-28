document.querySelectorAll('.lab-form').forEach(form => {
  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    const button = form.querySelector('button');
    button.disabled = true;
    const status = document.getElementById('lab-state');
    status.textContent = 'Ejecutando...';
    try {
      const response = await fetch(form.action, {method: 'POST', body: new FormData(form), credentials: 'same-origin'});
      if (!response.ok) throw new Error('No se pudo ejecutar la simulación. Comprueba tu sesión.');
      const data = await response.json();
      // textContent impide que el texto de ejemplo XSS se interprete como HTML.
      document.getElementById('lab-message').textContent = data.title + ': amenaza de prueba detectada y contenida.';
      document.getElementById('lab-detection').textContent = data.detection;
      document.getElementById('lab-defense').textContent = data.defense;
      document.getElementById('lab-evidence').textContent = JSON.stringify(data.evidence, null, 2);
      document.getElementById('lab-detail').hidden = false;
      status.textContent = '● Simulación completada';
    } catch (error) {
      status.textContent = 'Error de simulación';
      document.getElementById('lab-message').textContent = error.message;
    } finally { button.disabled = false; }
  });
});
