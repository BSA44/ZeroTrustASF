// static/script.js - Chat History & Roles Version
document.addEventListener('DOMContentLoaded', () => {
    // --- DOM Element References ---
    const chatOutput = document.getElementById('chat-output');
    const messageInput = document.getElementById('message-input');
    const sendButton = document.getElementById('send-button');
    const chatListUl = document.getElementById('chat-list');
    const newChatButton = document.getElementById('new-chat-button'); // Might be null for guests

    // --- State Variables ---
    let currentChatId = null;
    let initialData = {}; // To store data passed from Flask
    let chatDataCache = {}; // Simple cache for loaded chat content

    // --- Read Initial Data ---
    try {
        const dataElement = document.getElementById('initial-data');
        if (dataElement) {
            initialData = JSON.parse(dataElement.textContent);
        } else {
            console.error("Initial data script tag not found!");
            initialData = { chats: [], permissions: { can_create_chat: false, can_read_chat: false, role:'unknown' } };
        }
    } catch (e) {
        console.error("Failed to parse initial data:", e);
        initialData = { chats: [], permissions: { can_create_chat: false, can_read_chat: false, role:'unknown' } };
    }
    console.log("Initial Data Loaded:", initialData);

    // --- Helper Functions (Keep formatCodeBlocks, highlightElementContent) ---

    function formatCodeBlocks(text) { /* ... Keep implementation from previous step ... */
        if (!text) return '';
        const lines = text.split('\n'); let html = ''; let inCodeBlock = false; let codeLanguage = 'plaintext';
        for (const line of lines) {
            if (line.trim().startsWith('```')) {
                if (inCodeBlock) { html += '</code></pre>'; inCodeBlock = false; }
                else { codeLanguage = line.substring(3).trim() || 'plaintext'; codeLanguage = codeLanguage.replace(/[^a-zA-Z0-9-]/g, ''); html += `<pre><code class="language-${codeLanguage}">`; inCodeBlock = true; }
            } else {
                if (inCodeBlock) { const escapedLine = line.replace(/</g, "<").replace(/>/g, ">"); html += escapedLine + '\n'; }
                else { const escapedLine = line.replace(/</g, "<").replace(/>/g, ">"); html += escapedLine + '<br>'; }
            }
        }
        if (inCodeBlock) { html += '</code></pre>'; } if (html.endsWith('<br>')) { html = html.slice(0, -4); } return html;
     }

    function highlightElementContent(element) { /* ... Keep implementation from previous step ... */
        if (!element || typeof hljs === 'undefined') { if (typeof hljs === 'undefined') console.warn("highlight.js not loaded."); return; }
        element.querySelectorAll('pre code:not([data-highlighted])').forEach((block) => {
            try { hljs.highlightElement(block); block.dataset.highlighted = 'yes'; }
            catch (e) { console.error("Highlight.js error:", e); }
        });
     }

    function adjustTextareaHeight() { /* ... Keep implementation from previous step ... */
        messageInput.style.height = 'auto'; const scrollHeight = messageInput.scrollHeight;
        const maxHeightStyle = window.getComputedStyle(messageInput).maxHeight; const maxHeight = maxHeightStyle && maxHeightStyle !== 'none' ? parseInt(maxHeightStyle, 10) : 150;
        if (scrollHeight > maxHeight) { messageInput.style.height = `${maxHeight}px`; messageInput.style.overflowY = 'auto'; }
        else { messageInput.style.height = `${scrollHeight}px`; messageInput.style.overflowY = 'hidden'; }
    }

    /**
     * Adds a single message object to the chat output display.
     * @param {object} messageObj - Object like { sender: 'user'/'agent', content: '...' }
     */
    function displayMessage(messageObj) {
        if (!messageObj || !messageObj.sender || messageObj.content === undefined) return;

        const messageDiv = document.createElement('div');
        messageDiv.classList.add('message', messageObj.sender);

        const contentDiv = document.createElement('div');
        contentDiv.classList.add('message-content');

        // Format content (includes code highlighting)
        contentDiv.innerHTML = formatCodeBlocks(messageObj.content);
        highlightElementContent(contentDiv); // Highlight code in this specific message

        messageDiv.appendChild(contentDiv);
        chatOutput.appendChild(messageDiv);
    }

    /**
     * Clears the chat output area.
     */
    function clearChatOutput() {
        chatOutput.innerHTML = ''; // Remove all messages
    }

    /**
     * Displays a system message in the chat output.
     * @param {string} text - The message text.
     */
     function displaySystemMessage(text) {
         const messageDiv = document.createElement('div');
         messageDiv.classList.add('message', 'system');
         const contentDiv = document.createElement('div');
         contentDiv.classList.add('message-content');
         contentDiv.textContent = text;
         messageDiv.appendChild(contentDiv);
         chatOutput.appendChild(messageDiv);
         chatOutput.scrollTop = chatOutput.scrollHeight;
     }

    /**
     * Enables or disables the message input area and send button.
     * @param {boolean} enabled - True to enable, false to disable.
     */
    function setInputAreaEnabled(enabled) {
        messageInput.disabled = !enabled;
        sendButton.disabled = !enabled;
        if (!enabled) {
            messageInput.placeholder = "Select a chat or create a new one to send messages.";
        } else {
             messageInput.placeholder = "Enter your request...";
        }
    }

    /**
     * Loads and displays messages for a given chat ID.
     * @param {string} chatId - The ID of the chat to load.
     */
    async function loadChatContent(chatId) {
        if (!initialData.permissions.can_read_chat) {
            console.warn("Attempted to load chat without read permission.");
            displaySystemMessage("You do not have permission to read chats.");
            return;
        }
        if (!chatId) {
            clearChatOutput();
            displaySystemMessage("No chat selected.");
            setInputAreaEnabled(false);
            currentChatId = null;
            setActiveChatItem(null); // Deselect in list
            return;
        }

        console.log(`Loading content for chat: ${chatId}`);
        clearChatOutput();
        displaySystemMessage(`Loading chat ${chatId}...`); // Show loading message
        setInputAreaEnabled(false); // Disable input while loading

        // Check cache first (simple implementation)
        // if (chatDataCache[chatId]) {
        //     console.log("Using cached chat data.");
        //     renderChatMessages(chatDataCache[chatId].messages, chatId);
        //     return;
        // }

        try {
            const response = await fetch(`/chat/${chatId}`);
            if (!response.ok) {
                const errorData = await response.json().catch(() => ({ description: `HTTP error ${response.status}` }));
                throw new Error(errorData.description || `Failed to load chat (status ${response.status})`);
            }
            const chatData = await response.json();
            chatDataCache[chatId] = chatData; // Cache the data
            renderChatMessages(chatData.messages, chatId);

        } catch (error) {
            console.error(`Error loading chat ${chatId}:`, error);
            clearChatOutput();
            displaySystemMessage(`Error loading chat: ${error.message}`);
            currentChatId = null; // Reset current chat ID on error
             setActiveChatItem(null); // Deselect in list
        }
    }

    /**
     * Renders the messages for a loaded chat.
     * @param {Array} messages - Array of message objects.
     * @param {string} chatId - The ID of the currently loaded chat.
     */
    function renderChatMessages(messages, chatId) {
        clearChatOutput();
        if (!messages || messages.length === 0) {
            displaySystemMessage("This chat is empty. Send a message to start.");
        } else {
            messages.forEach(displayMessage);
        }
        // Scroll to bottom after rendering
        chatOutput.scrollTop = chatOutput.scrollHeight;
        currentChatId = chatId; // Set the currently active chat ID
         // Enable input only if user can create/send messages
        setInputAreaEnabled(initialData.permissions.can_create_chat);
        setActiveChatItem(chatId); // Highlight in list
    }


     /**
     * Sets the visual 'active' state for a chat list item.
     * @param {string|null} chatId - The ID of the chat to activate, or null to deactivate all.
     */
    function setActiveChatItem(chatId) {
        const items = chatListUl.querySelectorAll('li');
        items.forEach(item => {
            if (item.dataset.chatId === chatId) {
                item.classList.add('active');
            } else {
                item.classList.remove('active');
            }
        });
    }


    /**
     * Renders the list of chats in the sidebar.
     * @param {Array} chats - Array of chat objects {id: string, timestamp: string}.
     */
    function renderChatList(chats) {
        chatListUl.innerHTML = ''; // Clear existing list
        if (!chats || chats.length === 0) {
            chatListUl.innerHTML = '<li class="no-chats">No chats found.</li>';
            return;
        }

        chats.forEach(chat => {
            const li = document.createElement('li');
            li.dataset.chatId = chat.id; // Store chat ID on the element
            li.title = `Chat ID: ${chat.id}\nCreated: ${new Date(chat.timestamp).toLocaleString()}`; // Tooltip

            // Display a shorter ID or title if available, otherwise part of the timestamp
            const displayId = `Chat ${chat.id.substring(0, 8)}...`;
            const displayTime = new Date(chat.timestamp).toLocaleString();

            li.innerHTML = `${displayId} <span class="chat-timestamp">${displayTime}</span>`;

            // Add click listener to load chat content
            li.addEventListener('click', () => {
                loadChatContent(chat.id);
            });
            chatListUl.appendChild(li);
        });
    }


    /**
     * Handles creating a new chat.
     */
    async function handleNewChat() {
        if (!initialData.permissions.can_create_chat) return; // Should not be clickable anyway

        console.log("Attempting to create a new chat...");
        newChatButton.disabled = true; // Prevent double clicks

        try {
            const response = await fetch('/chat/new', { method: 'POST' });
            if (!response.ok) {
                const errorData = await response.json().catch(() => ({ description: `HTTP error ${response.status}` }));
                throw new Error(errorData.description || `Failed to create chat (status ${response.status})`);
            }
            const newChat = await response.json(); // Expecting { id: '...', timestamp: '...' }

            console.log("New chat created:", newChat);

            // Add to the top of the internal chat list and re-render
            initialData.chats.unshift(newChat); // Add to beginning
            renderChatList(initialData.chats);

            // Automatically load the new chat
            loadChatContent(newChat.id);

        } catch (error) {
            console.error("Error creating new chat:", error);
            displaySystemMessage(`Error creating chat: ${error.message}`); // Show error in main area
        } finally {
             if (newChatButton) newChatButton.disabled = false;
        }
    }


    /**
     * Handles sending a message to the currently active chat.
     */
    async function sendMessage() {
        const messageContent = messageInput.value.trim();
        if (!messageContent) return; // Ignore empty messages
        if (!currentChatId) {
            displaySystemMessage("Please select a chat before sending a message.");
            return;
        }
         if (!initialData.permissions.can_create_chat) {
             displaySystemMessage("You do not have permission to send messages.");
            return; // Double check permission
         }

        // 1. Display User Message Optimistically
        const userMessageObj = { sender: 'user', content: messageContent };
        displayMessage(userMessageObj);
        chatOutput.scrollTop = chatOutput.scrollHeight; // Scroll down

        // Clear input and disable controls
        messageInput.value = '';
        adjustTextareaHeight();
        setInputAreaEnabled(false); // Disable while waiting for response

        // 2. Add Loading Indicator (as a temporary system message perhaps?)
        const loadingMessageDiv = document.createElement('div');
        loadingMessageDiv.classList.add('message', 'agent'); // Mimic agent bubble
        loadingMessageDiv.innerHTML = `<div class="message-content"><div class="loading-dots"><span></span><span></span><span></span></div></div>`;
        chatOutput.appendChild(loadingMessageDiv);
        chatOutput.scrollTop = chatOutput.scrollHeight;


        // 3. Send message to backend
        try {
            console.log(`Sending message to chat ${currentChatId}...`);
            const response = await fetch(`/chat/${currentChatId}/message`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
                body: JSON.stringify({ message: messageContent }),
            });

            // Remove loading indicator regardless of outcome
             chatOutput.removeChild(loadingMessageDiv);

            if (!response.ok) {
                const errorData = await response.json().catch(() => ({ error: `HTTP error ${response.status}` }));
                 // Display backend error in chat
                displaySystemMessage(`Error sending message: ${errorData.error || errorData.description || `Status ${response.status}`}`);
                 // Re-add user message if needed (backend might not save on error)
                 // For simplicity, we leave the optimistically added user message.
                throw new Error(errorData.error || `Failed to send message (status ${response.status})`);
            }

            const data = await response.json(); // Expecting { user_message: {...}, agent_message: {...}, error?, warning? }

            console.log("Received response for message:", data);

            // 4. Display Agent Response
            // The backend now includes the agent message in the response
            if (data.agent_message) {
                 displayMessage(data.agent_message);
            }

             // Display warning if save failed
             if (data.warning) {
                 displaySystemMessage(`Warning: ${data.warning}`);
             }
             // Display agent error if one occurred during generation
              if (data.error) {
                  displaySystemMessage(`Agent error occurred: ${data.error}`);
              }

        } catch (error) {
             console.error('Error sending message:', error);
              // Remove loading indicator if it wasn't already removed (e.g., network error)
             if (chatOutput.contains(loadingMessageDiv)) {
                 chatOutput.removeChild(loadingMessageDiv);
             }
             // Display fetch/network error in chat
            displaySystemMessage(`Network or processing error: ${error.message}`);
        } finally {
            // 5. Re-enable input if a chat is still selected and user has permission
            if (currentChatId && initialData.permissions.can_create_chat) {
                setInputAreaEnabled(true);
                messageInput.focus(); // Focus input for convenience
            } else {
                 setInputAreaEnabled(false);
            }
            // Ensure scroll is at the bottom
            chatOutput.scrollTop = chatOutput.scrollHeight;
        }
    }


    // --- Event Listeners Setup ---

    // Send button click
    sendButton.addEventListener('click', sendMessage);

    // Textarea input for dynamic height adjustment
    messageInput.addEventListener('input', adjustTextareaHeight);

    // Textarea keydown for sending message on Enter (but not Shift+Enter)
    messageInput.addEventListener('keydown', (event) => {
        if (event.key === 'Enter' && !event.shiftKey) {
            event.preventDefault(); // Prevent default Enter behavior (newline)
             // Check if button is enabled before sending
            if (!sendButton.disabled) {
                 sendMessage();
            }
        }
    });

    // New Chat button click (only add listener if button exists)
    if (newChatButton) {
        newChatButton.addEventListener('click', handleNewChat);
    }

    // --- Initializations ---
    renderChatList(initialData.chats);
    adjustTextareaHeight();
    // Initially disable input until a chat is loaded/created
    setInputAreaEnabled(false);
    // Optional: Automatically load the first chat if one exists?
    // if (initialData.chats.length > 0 && initialData.permissions.can_read_chat) {
    //     loadChatContent(initialData.chats[0].id);
    // } else {
         displaySystemMessage("Select a chat from the list or create a new one.");
    // }

    console.log("Chat interface initialized (History & Roles mode).");
    console.warn("SECURITY WARNING: Role validation based solely on the 'zt-session' cookie value is insecure. This is for demonstration purposes only.");
});