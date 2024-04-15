// JavaScript for Slud9e Web Application

// Function to handle form submission
function handleSubmit(event) {
    event.preventDefault(); // Prevent default form submission

    // Get data from form input field
    const inputData = document.getElementById('dataInput').value;

    // Example: Send data to server via API endpoint
    sendDataToServer(inputData);
}

// Function to send data to server via API endpoint
function sendDataToServer(data) {
    // Example: Send data to server using Fetch API
    fetch('/api/data/submit', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ data: data })
    })
    .then(response => response.json())
    .then(result => {
        // Example: Display result on the webpage
        displayResult(result);
    })
    .catch(error => {
        console.error('Error:', error);
    });
}

// Function to display result on the webpage
function displayResult(result) {
    const dataDisplay = document.getElementById('dataDisplay');
    dataDisplay.innerText = result.message;
}

// Event listener for form submission
document.getElementById('dataForm').addEventListener('submit', handleSubmit);
