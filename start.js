// Simple start script to ensure correct path resolution
const path = require('path');
const { spawn } = require('child_process');

console.log('🚀 Starting Auth Service...');
console.log('📁 Current directory:', process.cwd());
console.log('📁 Server file path:', path.join(__dirname, 'src', 'server.js'));

// Start the server
const server = spawn('node', ['src/server.js'], {
    stdio: 'inherit',
    cwd: __dirname
});

server.on('error', (error) => {
    console.error('❌ Failed to start server:', error);
    process.exit(1);
});

server.on('exit', (code) => {
    console.log(`🛑 Server exited with code ${code}`);
    process.exit(code);
});
