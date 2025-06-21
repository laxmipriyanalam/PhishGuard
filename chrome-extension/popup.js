document.addEventListener('DOMContentLoaded', function () {
  chrome.tabs.query({ active: true, currentWindow: true }, function (tabs) {
    const currentUrl = tabs[0].url;

    document.getElementById('url-display').innerText = currentUrl;

    // Send to Flask backend
    fetch('http://127.0.0.1:5000/predict', {
      method: 'POST',
      body: JSON.stringify({ url: currentUrl }),
      headers: {
        'Content-Type': 'application/json'
      }
    })
    .then(response => response.json())
    .then(data => {
      const resultDiv = document.getElementById('result');
      if (data.result === 'Phishing') {
        resultDiv.innerHTML = '❌ This URL is <b>PHISHING</b>';
        resultDiv.style.color = 'red';
      } else if (data.result === 'Safe') {
        resultDiv.innerHTML = '✅ This URL is <b>SAFE</b>';
        resultDiv.style.color = 'green';
      } else {
        resultDiv.innerHTML = '⚠️ Could not evaluate.';
        resultDiv.style.color = 'gray';
      }
    })
    .catch(err => {
      console.error('Error:', err);
      document.getElementById('result').innerText = '⚠️ Backend not reachable.';
    });
  });
});
