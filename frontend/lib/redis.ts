import { createClient } from 'redis';

const client = createClient({
username: process.env.REDIS_USER,
password: process.env.REDIS_PASSWORD,
socket: {
host: process.env.REDIS_HOST,
port: Number(process.env.REDIS_PORT),
},
});

client.on('error', err => {
console.error('Redis Client Error', err);
});

// we connect once and reuse the single client
async function connectRedis() {
if (!client.isOpen) {
await client.connect();
console.log('✅ Connected to Redis');
}
}
connectRedis().catch(console.error);

export default client;