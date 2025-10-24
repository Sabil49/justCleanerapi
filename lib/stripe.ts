// lib/stripe.ts
import Stripe from 'stripe';

export const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!, {
  apiVersion: '2024-12-18.acacia',
});

export const PLANS = {
  monthly: {
    priceId: process.env.STRIPE_PREMIUM_MONTHLY_PRICE_ID!,
    name: 'Premium Monthly',
    price: 4.99,
    interval: 'month',
  },
  yearly: {
    priceId: process.env.STRIPE_PREMIUM_YEARLY_PRICE_ID!,
    name: 'Premium Yearly',
    price: 49.99,
    interval: 'year',
  },
};