import { useState, useRef, useEffect } from 'react';
import { Client } from '@langchain/langgraph-sdk';
import ReactMarkdown from 'react-markdown';
import './ChatInterface.css';

interface Message {
  role: 'user' | 'assistant';
  content: string;
  timestamp: Date;
}

export default function ChatInterface() {
  const [messages, setMessages] = useState<Message[]>([]);
  const [input, setInput] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [threadId, setThreadId] = useState<string | null>(null);
  const messagesEndRef = useRef<HTMLDivElement>(null);

  // Initialize LangGraph client
  const client = new Client({
    apiUrl: 'http://127.0.0.1:2024',
  });

  // Auto-scroll to bottom when new messages arrive
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  // Create a new thread on component mount or restore from localStorage
  useEffect(() => {
    const initThread = async () => {
      try {
        // Check if we have a saved thread ID
        const savedThreadId = localStorage.getItem('langgraph_thread_id');

        if (savedThreadId) {
          // Try to verify the thread still exists and load its history
          try {
            const threadState = await client.threads.getState(savedThreadId);
            setThreadId(savedThreadId);
            console.log('Thread restored from localStorage:', savedThreadId);

            // Load conversation history from the thread
            if (threadState.values?.messages && threadState.values.messages.length > 0) {
              const loadedMessages: Message[] = threadState.values.messages
                .filter((msg: any) => msg.type === 'human' || msg.type === 'ai')
                .map((msg: any) => ({
                  role: msg.type === 'human' ? 'user' : 'assistant',
                  content: typeof msg.content === 'string' ? msg.content :
                           Array.isArray(msg.content) ? msg.content.map((c: any) => c.text || c.content || '').join('') :
                           msg.content?.text || msg.content?.content || '',
                  timestamp: new Date(msg.id || Date.now()),
                }));
              setMessages(loadedMessages);
              console.log('Loaded', loadedMessages.length, 'messages from thread history');
            }
          } catch (error) {
            // Thread doesn't exist anymore, create a new one
            console.log('Saved thread not found, creating new thread');
            const thread = await client.threads.create();
            setThreadId(thread.thread_id);
            localStorage.setItem('langgraph_thread_id', thread.thread_id);
            console.log('New thread created:', thread.thread_id);
          }
        } else {
          // No saved thread, create a new one
          const thread = await client.threads.create();
          setThreadId(thread.thread_id);
          localStorage.setItem('langgraph_thread_id', thread.thread_id);
          console.log('New thread created:', thread.thread_id);
        }
      } catch (error) {
        console.error('Error initializing thread:', error);
      }
    };
    initThread();
  }, []);

  const startNewChat = async () => {
    try {
      // Create a new thread
      const thread = await client.threads.create();
      setThreadId(thread.thread_id);
      localStorage.setItem('langgraph_thread_id', thread.thread_id);

      // Clear messages
      setMessages([]);
      setInput('');

      console.log('New chat started with thread:', thread.thread_id);
    } catch (error) {
      console.error('Error starting new chat:', error);
    }
  };

  const sendMessage = async () => {
    if (!input.trim() || !threadId || isLoading) return;

    const userMessage: Message = {
      role: 'user',
      content: input,
      timestamp: new Date(),
    };

    setMessages((prev) => [...prev, userMessage]);
    setInput('');
    setIsLoading(true);

    try {
      // Send message to the agent
      const streamResponse = client.runs.stream(
        threadId,
        'agent', // This matches the graph name in langgraph.json
        {
          input: {
            messages: [{ role: 'user', content: input }],
          },
          streamMode: 'values',
        }
      );

      let assistantContent = '';

      // Stream the response
      for await (const chunk of streamResponse) {
        console.log('Received chunk:', chunk);

        if (chunk.event === 'values') {
          // Get the messages from the state
          const state = chunk.data;
          if (state && state.messages && state.messages.length > 0) {
            const lastMessage = state.messages[state.messages.length - 1];
            console.log('Last message:', lastMessage);

            // Handle different content formats
            if (lastMessage.content) {
              if (typeof lastMessage.content === 'string') {
                assistantContent = lastMessage.content;
              } else if (Array.isArray(lastMessage.content)) {
                // Handle array of content blocks
                assistantContent = lastMessage.content
                  .map((block: any) => {
                    if (typeof block === 'string') return block;
                    if (block.text) return block.text;
                    if (block.content) return block.content;
                    return '';
                  })
                  .filter(Boolean)
                  .join('');
              } else if (typeof lastMessage.content === 'object') {
                // Handle single content object
                assistantContent = lastMessage.content.text || lastMessage.content.content || '';
              }
            }
          }
        }
      }

      console.log('Final assistant content:', assistantContent);

      // Add assistant's response
      if (assistantContent) {
        const assistantMessage: Message = {
          role: 'assistant',
          content: assistantContent,
          timestamp: new Date(),
        };
        setMessages((prev) => [...prev, assistantMessage]);
      } else {
        // If no content, show a message
        const assistantMessage: Message = {
          role: 'assistant',
          content: 'No response received from agent.',
          timestamp: new Date(),
        };
        setMessages((prev) => [...prev, assistantMessage]);
      }
    } catch (error) {
      console.error('Error sending message:', error);
      const errorMessage: Message = {
        role: 'assistant',
        content: `Error: ${error instanceof Error ? error.message : 'Failed to send message'}`,
        timestamp: new Date(),
      };
      setMessages((prev) => [...prev, errorMessage]);
    } finally {
      setIsLoading(false);
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      sendMessage();
    }
  };

  const clearChat = async () => {
    await startNewChat();
  };

  return (
    <div className="chat-container">
      <div className="chat-header">
        <h1>DeepSense Firewall Console</h1>
        <div className="header-info">
          <span className="thread-id">Session: {threadId?.slice(0, 8)}...</span>
          <button onClick={clearChat} className="clear-btn" title="Start a new conversation">
            New Session
          </button>
        </div>
      </div>

      <div className="messages-container">
        {messages.length === 0 && (
          <div className="welcome-message">
            <h2>DeepSense Firewall Management</h2>
            <p>AI-powered pfSense firewall management. Try asking:</p>
            <ul>
              <li>"Show me all connected clients"</li>
              <li>"Get system health for opus-1"</li>
              <li>"Analyze blocked traffic for the last 7 days"</li>
              <li>"Perform a security assessment on opus-1"</li>
              <li>"What port forwarding rules are configured?"</li>
            </ul>
          </div>
        )}

        {messages.map((message, index) => (
          <div key={index} className={`message ${message.role}`}>
            <div className="message-header">
              <span className="role">
                {message.role === 'user' ? '👤 You' : '🤖 Agent'}
              </span>
              <span className="timestamp">
                {message.timestamp.toLocaleTimeString()}
              </span>
            </div>
            <div className="message-content">
              {message.role === 'assistant' ? (
                <ReactMarkdown>{typeof message.content === 'string' ? message.content : JSON.stringify(message.content)}</ReactMarkdown>
              ) : (
                <div style={{ whiteSpace: 'pre-wrap' }}>
                  {typeof message.content === 'string' ? message.content : JSON.stringify(message.content)}
                </div>
              )}
            </div>
          </div>
        ))}

        {isLoading && (
          <div className="message assistant loading">
            <div className="message-header">
              <span className="role">🤖 Agent</span>
            </div>
            <div className="message-content">
              <div className="typing-indicator">
                <span></span>
                <span></span>
                <span></span>
              </div>
            </div>
          </div>
        )}

        <div ref={messagesEndRef} />
      </div>

      <div className="input-container">
        <textarea
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={handleKeyDown}
          placeholder="Type your message... (Enter to send, Shift+Enter for new line)"
          disabled={isLoading || !threadId}
          rows={3}
        />
        <button
          onClick={sendMessage}
          disabled={!input.trim() || isLoading || !threadId}
          className="send-btn"
        >
          {isLoading ? '⏳' : '📤'} Send
        </button>
      </div>
    </div>
  );
}

