
        const checkIntervalMs = 5000; // Interval from Flask template
        const sessionCheckEndpoint = "https://192.168.22.25/session/check"; // Endpoint URL from Flask
        

        function performSessionCheck() {
            console.log(`[${new Date().toISOString()}] Performing session check...`);
            

            fetch(sessionCheckEndpoint, {
                method: 'POST',
                // Body can be empty for this check, server uses headers/cookie
                headers: {
                    'Accept': 'application/json'
                },
                 // Crucial for sending the session cookie automatically if hosted on a different
                 // subdomain/port during development (less relevant for same-origin Nginx setup)
                 // For same-origin, browser usually handles cookie sending correctly.
                 // credentials: 'include'
            })
            .then(response => {
                console.log(`[${new Date().toISOString()}] Check response status: ${response.status}`);
                if (response.ok) { // Status 200-299
                    statusElement.textContent = `Status: Session OK (Last check: ${new Date().toLocaleTimeString()})`;
                    return response.json(); // Optional: process success response if needed
                } else if (response.status === 401 || response.status === 403) {
                    // Session is invalid (expired, revoked due to context change, etc.)
                    console.error(`[${new Date().toISOString()}] Session check failed: Unauthorized/Forbidden (${response.status}). Session likely revoked.`);
                    // Optionally, redirect to login page or show an error message
                    alert('Your session is no longer valid due to a change in context or expiration. You will be redirected.');
                    window.location.href = '/session/init'; // Redirect to init page (or a real login page)
                    throw new Error(`Session Invalid (${response.status})`); // Stop further processing/interval
                } else {
                    // Other server errors (5xx) or unexpected client errors (4xx)
                    console.error(`[${new Date().toISOString()}] Session check failed with status: ${response.status}`);
                    statusElement.textContent = `Status: Error checking session (${response.status}) at ${new Date().toLocaleTimeString()}. Retrying later.`;
                    statusElement.style.color = 'orange';
                    // Don't necessarily redirect immediately on server errors, maybe retry later
                    throw new Error(`Server Error (${response.status})`);
                }
            })
            .then(data => {
                if (data) {
                    console.log(`[${new Date().toISOString()}] Session check successful:`, data);
                }
            })
            .catch(error => {
                // Handle network errors or errors thrown above
                console.error(`[${new Date().toISOString()}] Error during session check fetch:`, error.message);
                 if (!error.message.includes('Session Invalid')) { // Avoid double message
                     
                     statusElement.style.color = 'red';
                 }
                // Consider stopping the interval if errors persist or are critical
                // clearInterval(intervalId); // Example: Stop checking on error
            });
        }

        // Perform the first check immediately on load
        performSessionCheck();

        // Schedule subsequent checks
        const intervalId = setInterval(performSessionCheck, checkIntervalMs);
     