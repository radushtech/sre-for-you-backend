const express = require('express');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const Razorpay = require('razorpay');
const { createClient } = require('@supabase/supabase-js');
const crypto = require('crypto');

const app = express();
app.use(express.json({
  verify: (req, res, buf) => { req.rawBody = buf; }
}));
app.use(cors({ origin: process.env.FRONTEND_URL }));

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SECRET_KEY
);

const razorpay = new Razorpay({
  key_id: process.env.RAZORPAY_KEY_ID,
  key_secret: process.env.RAZORPAY_KEY_SECRET
});

const VALIDATION_AMOUNT_PAISE = 100;       // Re 1
const ROADMAP_AMOUNT_PAISE = 3999900;      // Rs 39,999

function generateToken() {
  return crypto.randomBytes(32).toString('hex');
}

// Verifies a Razorpay signature against the amount/status Razorpay ACTUALLY
// recorded for that payment (not just what the client claims), and confirms
// the order_id belongs to the access_token making the request.
// This is the core of the fix: previously any valid signature could be
// replayed against a different endpoint/order because ownership was never
// checked, only cryptographic validity of the signature itself.
async function verifyPaymentOwnership({
  razorpay_order_id,
  razorpay_payment_id,
  razorpay_signature,
  expectedOrderId,
  expectedAmountPaise
}) {
  if (!razorpay_order_id || !razorpay_payment_id || !razorpay_signature) {
    return { ok: false, reason: 'Missing payment fields' };
  }

  // 1. Signature must be cryptographically valid.
  const sign = razorpay_order_id + '|' + razorpay_payment_id;
  const expectedSignature = crypto
    .createHmac('sha256', process.env.RAZORPAY_KEY_SECRET)
    .update(sign)
    .digest('hex');
  if (expectedSignature !== razorpay_signature) {
    return { ok: false, reason: 'Invalid payment signature' };
  }

  // 2. The order being verified must be the SAME order we created and
  //    stored against this access_token — not just any validly-signed order.
  //    This is what stops a validation-payment signature from being
  //    replayed against the roadmap-payment endpoint (or vice versa).
  if (!expectedOrderId || razorpay_order_id !== expectedOrderId) {
    return { ok: false, reason: 'Order does not belong to this session' };
  }

  // 3. Confirm directly with Razorpay (not just trusting the client) that
  //    the payment was actually captured and for the expected amount.
  const payment = await razorpay.payments.fetch(razorpay_payment_id);
  if (payment.order_id !== razorpay_order_id) {
    return { ok: false, reason: 'Payment/order mismatch' };
  }
  if (payment.status !== 'captured') {
    return { ok: false, reason: 'Payment not captured' };
  }
  if (payment.amount !== expectedAmountPaise) {
    return { ok: false, reason: 'Payment amount mismatch' };
  }

  return { ok: true, payment };
}

// Health check
app.get('/', (req, res) => {
  res.json({ status: 'SRE for You backend is running' });
});

// Register and create Re1 validation order
app.post('/api/register', async (req, res) => {
  try {
    const { full_name, email, company, designation, phone } = req.body;
    if (!full_name || !email || !company) {
      return res.status(400).json({ error: 'Name, email and company are required' });
    }
    const { data: existing } = await supabase
      .from('registrations')
      .select('id, validation_paid, access_token')
      .eq('email', email)
      .single();
    if (existing && existing.validation_paid) {
      return res.json({ already_registered: true, access_token: existing.access_token });
    }
    const order = await razorpay.orders.create({
      amount: VALIDATION_AMOUNT_PAISE,
      currency: 'INR',
      receipt: 'validation_' + Date.now()
    });
    const access_token = generateToken();
    if (existing) {
      await supabase.from('registrations').update({
        full_name, company, designation, phone,
        validation_order_id: order.id,
        access_token
      }).eq('email', email);
    } else {
      await supabase.from('registrations').insert({
        full_name, email, company, designation, phone,
        validation_order_id: order.id,
        access_token
      });
    }
    res.json({ order_id: order.id, amount: VALIDATION_AMOUNT_PAISE, currency: 'INR', access_token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Registration failed' });
  }
});

// Verify Re1 validation payment
app.post('/api/verify-validation', async (req, res) => {
  try {
    const { razorpay_order_id, razorpay_payment_id, razorpay_signature, access_token } = req.body;

    const { data: reg } = await supabase
      .from('registrations')
      .select('id, validation_order_id')
      .eq('access_token', access_token)
      .single();
    if (!reg) {
      return res.status(401).json({ error: 'Invalid access token' });
    }

    const result = await verifyPaymentOwnership({
      razorpay_order_id,
      razorpay_payment_id,
      razorpay_signature,
      expectedOrderId: reg.validation_order_id,
      expectedAmountPaise: VALIDATION_AMOUNT_PAISE
    });
    if (!result.ok) {
      return res.status(400).json({ error: result.reason });
    }

    await supabase.from('registrations').update({
      validation_paid: true,
      validation_payment_id: razorpay_payment_id
    }).eq('access_token', access_token);
    res.json({ success: true, access_token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Verification failed' });
  }
});

// Verify access token
app.post('/api/verify-token', async (req, res) => {
  try {
    const { access_token } = req.body;
    const { data } = await supabase.from('registrations')
      .select('id, validation_paid, roadmap_paid, roadmap_generated')
      .eq('access_token', access_token)
      .single();
    if (!data || !data.validation_paid) {
      return res.status(401).json({ error: 'Invalid or unpaid token' });
    }
    res.json({ valid: true, roadmap_paid: data.roadmap_paid, roadmap_generated: data.roadmap_generated });
  } catch (err) {
    res.status(500).json({ error: 'Token verification failed' });
  }
});

// Create roadmap payment order
app.post('/api/create-roadmap-payment', async (req, res) => {
  try {
    const { access_token } = req.body;
    const { data } = await supabase.from('registrations')
      .select('id, validation_paid, roadmap_paid')
      .eq('access_token', access_token)
      .single();
    if (!data || !data.validation_paid) {
      return res.status(401).json({ error: 'Access denied' });
    }
    if (data.roadmap_paid) {
      return res.json({ already_paid: true });
    }
    const order = await razorpay.orders.create({
      amount: ROADMAP_AMOUNT_PAISE,
      currency: 'INR',
      receipt: 'roadmap_' + Date.now()
    });
    await supabase.from('registrations').update({
      roadmap_order_id: order.id
    }).eq('access_token', access_token);
    res.json({ order_id: order.id, amount: ROADMAP_AMOUNT_PAISE, currency: 'INR' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Payment creation failed' });
  }
});

// Verify roadmap payment
app.post('/api/verify-roadmap-payment', async (req, res) => {
  try {
    const { razorpay_order_id, razorpay_payment_id, razorpay_signature, access_token } = req.body;

    const { data: reg } = await supabase
      .from('registrations')
      .select('id, roadmap_order_id')
      .eq('access_token', access_token)
      .single();
    if (!reg) {
      return res.status(401).json({ error: 'Invalid access token' });
    }

    const result = await verifyPaymentOwnership({
      razorpay_order_id,
      razorpay_payment_id,
      razorpay_signature,
      expectedOrderId: reg.roadmap_order_id,
      expectedAmountPaise: ROADMAP_AMOUNT_PAISE
    });
    if (!result.ok) {
      return res.status(400).json({ error: result.reason });
    }

    await supabase.from('registrations').update({
      roadmap_paid: true,
      roadmap_payment_id: razorpay_payment_id
    }).eq('access_token', access_token);
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Verification failed' });
  }
});

// Generate roadmap via Anthropic
app.post('/api/generate-roadmap', async (req, res) => {
  try {
    const { access_token, prompt } = req.body;
    const { data } = await supabase.from('registrations')
      .select('roadmap_paid')
      .eq('access_token', access_token)
      .single();
    if (!data || !data.roadmap_paid) {
      return res.status(401).json({ error: 'Payment required' });
    }
    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': process.env.ANTHROPIC_API_KEY,
        'anthropic-version': '2023-06-01'
      },
      body: JSON.stringify({
        model: 'claude-sonnet-4-6',
        max_tokens: 4000,
        messages: [{ role: 'user', content: prompt }]
      })
    });
    const aiData = await response.json();
    await supabase.from('registrations').update({ roadmap_generated: true }).eq('access_token', access_token);
    res.json(aiData);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Roadmap generation failed' });
  }
});

// ---------------------------------------------------------------------
// TEMPORARY BRIDGE — no auth, no payment gate, rate-limited.
// Restored so the frontend can be smoke-tested and demoed while the
// registration/payment UI flow is still being built. Remove this route
// once assessment3.html is wired to the real /api/generate-roadmap flow
// (register -> validation payment -> roadmap payment -> generate-roadmap
// with access_token). Do not ship this to a real partner-facing deploy
// long-term: it exposes the Anthropic key's usage to anyone who can reach
// this URL, just without the raw key itself being visible client-side.
// ---------------------------------------------------------------------
const publicRoadmapLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10,                  // 10 requests per IP per window
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many roadmap requests from this IP, please try again later.' }
});

app.post('/api/generate-roadmap-public', publicRoadmapLimiter, async (req, res) => {
  try {
    const { prompt } = req.body;
    if (!prompt) {
      return res.status(400).json({ error: 'Missing prompt' });
    }
    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': process.env.ANTHROPIC_API_KEY,
        'anthropic-version': '2023-06-01'
      },
      body: JSON.stringify({
        model: 'claude-sonnet-4-6',
        max_tokens: 4000,
        messages: [{ role: 'user', content: prompt }]
      })
    });
    const aiData = await response.json();
    res.json(aiData);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Roadmap generation failed' });
  }
});

// Razorpay webhook — server-to-server safety net alongside the client-side
// verify calls above. Catches payments that succeeded on Razorpay's side
// but whose browser confirmation never arrived (closed tab, network drop,
// crash, etc). Configure in Razorpay Dashboard -> Settings -> Webhooks,
// pointing at <this service URL>/api/webhook, subscribed to at least
// payment.captured (payment.failed recommended too). The webhook secret
// shown at creation time must be set as RAZORPAY_WEBHOOK_SECRET here.
app.post('/api/webhook', async (req, res) => {
  try {
    const signature = req.headers['x-razorpay-signature'];
    if (!signature || !req.rawBody) {
      return res.status(400).send('Missing signature or body');
    }

    const expectedSignature = crypto
      .createHmac('sha256', process.env.RAZORPAY_WEBHOOK_SECRET)
      .update(req.rawBody)
      .digest('hex');

    const signaturesMatch =
      Buffer.byteLength(signature) === Buffer.byteLength(expectedSignature) &&
      crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expectedSignature));

    if (!signaturesMatch) {
      console.error('Webhook signature mismatch');
      return res.status(400).send('Invalid signature');
    }

    const event = req.body.event;
    const payment = req.body.payload && req.body.payload.payment && req.body.payload.payment.entity;

    // Always 200 once the signature is valid, even for events we don't
    // act on below — Razorpay retries on non-2xx responses, and retrying
    // an event we deliberately ignore just adds noise.
    if (!payment || event !== 'payment.captured') {
      return res.status(200).send('Ignored');
    }

    const orderId = payment.order_id;
    const paymentId = payment.id;

    const { data: byValidation } = await supabase
      .from('registrations')
      .select('id, validation_paid')
      .eq('validation_order_id', orderId)
      .single();

    if (byValidation) {
      if (!byValidation.validation_paid) {
        await supabase.from('registrations').update({
          validation_paid: true,
          validation_payment_id: paymentId
        }).eq('id', byValidation.id);
      }
      return res.status(200).send('OK');
    }

    const { data: byRoadmap } = await supabase
      .from('registrations')
      .select('id, roadmap_paid')
      .eq('roadmap_order_id', orderId)
      .single();

    if (byRoadmap) {
      if (!byRoadmap.roadmap_paid) {
        await supabase.from('registrations').update({
          roadmap_paid: true,
          roadmap_payment_id: paymentId
        }).eq('id', byRoadmap.id);
      }
      return res.status(200).send('OK');
    }

    // Order ID didn't match any known registration — log for investigation
    // but still ack so Razorpay doesn't keep retrying.
    console.error('Webhook: no registration found for order_id', orderId);
    res.status(200).send('No matching registration');
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Webhook processing failed' });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log('SRE for You backend running on port ' + PORT));
