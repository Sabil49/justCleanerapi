// app/api/device/report/route.ts
import { NextRequest, NextResponse } from 'next/server';
import { prisma } from '@/lib/db';
import { requireAuth } from '@/lib/auth';

export async function POST(request: NextRequest) {
  try {
    const user = requireAuth(request);
    const { storageUsed, storageFreed, deviceName, osVersion } = await request.json();

    if (storageUsed === undefined || storageFreed === undefined || !deviceName) {
      return NextResponse.json(
        { error: 'Missing required fields' },
        { status: 400 }
      );
    }

    const report = await prisma.report.create({
      data: {
        userId: user.userId,
        storageUsed,
        storageFreed,
        deviceName,
        osVersion,
      },
    });

    return NextResponse.json({
      report,
      message: 'Report saved successfully',
    }, { status: 201 });

  } catch (error: any) {
    console.error('Report error:', error);
    
    if (error.message === 'Unauthorized') {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
}

export async function GET(request: NextRequest) {
  try {
    const user = requireAuth(request);

    const reports = await prisma.report.findMany({
      where: { userId: user.userId },
      orderBy: { timestamp: 'desc' },
      take: 20,
    });

    const totalFreed = await prisma.report.aggregate({
      where: { userId: user.userId },
      _sum: { storageFreed: true },
    });

    return NextResponse.json({
      reports,
      totalSpaceFreed: totalFreed._sum.storageFreed || 0,
    });

  } catch (error: any) {
    console.error('Get reports error:', error);
    
    if (error.message === 'Unauthorized') {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
}