import { TinfoilAI } from '../../src';
import { config } from 'dotenv';

config();
process.env.TINFOIL_ENCLAVE = process.env.TINFOIL_ENCLAVE || "llama3-3-70b.model.tinfoil.sh";
process.env.TINFOIL_REPO = process.env.TINFOIL_REPO || "tinfoilsh/confidential-llama3-3-70b";

async function runStreamingExample(client: TinfoilAI) {
    const messages = [
        { role: 'system' as const, content: 'You are a helpful assistant.' },
        { role: 'user' as const, content: 'Tell me a short story about aluminum foil.' }
    ];

    console.log('\nPrompts:');
    messages.forEach(msg => {
        console.log(`${msg.role.toUpperCase()}: ${msg.content}`);
    });

    try {
        console.log('Creating chat completion stream...');
        const stream = await client.chat.completions.create({
            model: 'llama3-3-70b',
            messages: messages,
            stream: true,
        });

        console.log('\nStreaming response:');
        let fullResponse = '';

        for await (const chunk of stream) {
            const content = chunk.choices[0]?.delta?.content || '';
            fullResponse += content;
            process.stdout.write(content);
        }

        console.log('\n\nFull accumulated response:');
        console.log(fullResponse);
    } catch (error) {
        console.error('Stream error:', error);
        if (error instanceof Error) {
            console.error('Full error stack:', error.stack);
        }
        // Log any additional error properties
        console.error('Error details:', JSON.stringify(error, null, 2));
    }
}

async function main() {
    try {
        console.log('Environment configuration:');
        console.log('TINFOIL_ENCLAVE:', process.env.TINFOIL_ENCLAVE);
        console.log('TINFOIL_REPO:', process.env.TINFOIL_REPO);

        // Create a new TinfoilAI
        const client = new TinfoilAI({
            apiKey: 'tinfoil' // Replace with your actual API key
        });

        // Run streaming example
        await runStreamingExample(client);
    } catch (error) {
        console.error('Main error:', error);
        if (error instanceof Error) {
            console.error('Main error stack:', error.stack);
        }
        throw error;
    }
}

// Run the example
main().catch(error => {
    console.error('Top level error:', error);
    process.exit(1);
});
