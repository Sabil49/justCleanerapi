// app/api/device/clean/route.ts
import { NextRequest, NextResponse } from 'next/server';
import { prisma } from '@/lib/db';
import { requireAuth } from '@/lib/auth';

export async function POST(request: NextRequest) {
  try {
    const user = await requireAuth(request);
    const { cleanType, filesRemoved, spaceFreed } = await request.json();

    if (!cleanType || filesRemoved === undefined || spaceFreed === undefined) {
      return NextResponse.json(
        { error: 'Missing required fields' },
        { status: 400 }
      );
    }

    const cleanLog = await prisma.cleanLog.create({
      data: {
        userId: user.userId,
        cleanType,
        filesRemoved,
        spaceFreed,
      },
    });

    return NextResponse.json({
      cleanLog,
      message: 'Clean operation logged successfully',
    }, { status: 201 });

  } catch (error: any) {
    console.error('Clean log error:', error);
    
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
    const user = await requireAuth(request);

    const logs = await prisma.cleanLog.findMany({
      where: { userId: user.userId },
      orderBy: { timestamp: 'desc' },
      take: 50,
    });

    const summary = await prisma.cleanLog.groupBy({
      by: ['cleanType'],
      where: { userId: user.userId },
      _sum: {
        filesRemoved: true,
        spaceFreed: true,
      },
      _count: true,
    });

    return NextResponse.json({
      logs,
      summary,
    });

  } catch (error: any) {
    console.error('Get clean logs error:', error);
    
    if (error.message === 'Unauthorized') {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
}