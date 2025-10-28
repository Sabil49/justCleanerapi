// app/api/subscription/plans/route.ts
import { NextResponse } from 'next/server';
import { PLANS } from '@/lib/stripe';

export async function GET() {
  try {
    const plans = [
      {
        id: 'monthly',
        name: PLANS.monthly.name,
        price: PLANS.monthly.price,
        interval: PLANS.monthly.interval,
        features: [
          'Deep cleaning (hidden cache)',
          'Scheduled auto-clean',
          'Cloud backups for reports',
          'Battery optimization automation',
          'Ad-free experience',
          'Priority support',
        ],
      },
      {
        id: 'yearly',
        name: PLANS.yearly.name,
        price: PLANS.yearly.price,
        interval: PLANS.yearly.interval,
        savings: '17%',
        features: [
          'Deep cleaning (hidden cache)',
          'Scheduled auto-clean',
          'Cloud backups for reports',
          'Battery optimization automation',
          'Ad-free experience',
          'Priority support',
          '2 months free',
        ],
      },
    ];

    return NextResponse.json({ plans });

  } catch (error) {
    console.error('Get plans error:', error);
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
}