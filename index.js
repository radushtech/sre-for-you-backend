const express = require('express');
const cors = require('cors');
const Razorpay = require('razorpay');
const { createClient } = require('@supabase/supabase-js');
const crypto = require('crypto');

const app = express();
app.use(express.json());
app.use(cors({ origin: process.env.FRONTEND_URL }));

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SECRET_KEY
);

const razorpay = new Razorpay({
  key_id: process.env.RAZORPAY_KEY_ID,
  key_secret: process.env.RAZORPAY_KEY_SECRET
});

function generateToken() {
  return crypto.randomBytes(32).toString('hex');
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
      amount: 100,
      currency: 'INR',
      receipt: 'validation_' + Date.now()
    });
    const access_token = generateToken();
    if (existing) {
      await supabase.from('registrations').update({
        full_name, company, designation, phone,
        validation_payment_id: order.id, access_token
      }).eq('email', email);
    } else {
      await supabase.from('registrations').insert({
        full_name, email, company, designation, phone,
        validation_payment_id: order.id, access_token
      });
    }
    res.json({ order_id: order.id, amount: 100, currency: 'INR', access_token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Registration failed' });
  }
});

// Verify Re1 validation payment
app.post('/api/verify-validation', async (req, res) => {
  try {
    const { razorpay_order_id, razorpay_payment_id, razorpay_signature, access_token } = req.body;
    const sign = razorpay_order_id + '|' + razorpay_payment_id;
    const expected = crypto.createHmac('sha256', process.env.RAZORPAY_KEY_SECRET).update(sign).digest('hex');
    if (expected !== razorpay_signature) {
      return res.status(400).json({ error: 'Invalid payment signature' });
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

// Create INR 39999 roadmap payment order
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
      amount: 3999900,
      currency: 'INR',
      receipt: 'roadmap_' + Date.now()
    });
    res.json({ order_id: order.id, amount: 3999900, currency: 'INR' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Payment creation failed' });
  }
});

// Verify INR 39999 roadmap payment
app.post('/api/verify-roadmap-payment', async (req, res) => {
  try {
    const { razorpay_order_id, razorpay_payment_id, razorpay_signature, access_token } = req.body;
    const sign = razorpay_order_id + '|' + razorpay_payment_id;
    const expected = crypto.createHmac('sha256', process.env.RAZORPAY_KEY_SECRET).update(sign).digest('hex');
    if (expected !== razorpay_signature) {
      return res.status(400).json({ error: 'Invalid payment signature' });
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

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log('SRE for You backend running on port ' + PORT));
