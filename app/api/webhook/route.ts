export async function GET() {
    return new Response("Webhook received", { status: 200 });
}