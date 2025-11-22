// lib/cost.ts
export const BASE_HOURLY = 20;
export const BASE_DAILY = 100;
export const BASE_MONTHLY = 2000;

function sigmoid(x: number): number {
  return 1 / (1 + Math.exp(-x));
}

export function getOccupancyMultiplier(
  occupied: number,
  total: number,
  threshold = 0.4
): number {
  const occupancyRatio = occupied / total;
  const slope = 10;
  const x = slope * (occupancyRatio - threshold);
  const multiplier = 1 + sigmoid(x); // scale from 1→2
  return parseFloat(multiplier.toFixed(2));
}

export function getDemandMultiplier(start: Date): number {
  const hour = start.getHours();
  // Peak: 8–10am, 5–7pm
  if ((hour >= 8 && hour <= 10) || (hour >= 17 && hour <= 19)) {
    return 1.5;
  }
  return 1.0;
}

export function getLoyaltyDiscount(cost: number, points: number): number {
  return Math.min(cost * 0.3, points); // max 30% off
}

export function calculateFinalCost(
  hours: number,
  days: number,
  months: number,
  start: Date,
  occupied: number,
  total: number,
  isSubscriber: boolean,
  loyaltyPoints: number
): number {
  const baseCost =
    months * BASE_MONTHLY + days * BASE_DAILY + hours * BASE_HOURLY;
  const timeMultiplier = getDemandMultiplier(start);
  const occupancyMultiplier = getOccupancyMultiplier(occupied, total);
  let cost = baseCost * timeMultiplier * occupancyMultiplier;

  if (isSubscriber) cost *= 0.8; // 20% off for subscribers
  const discount = getLoyaltyDiscount(cost, loyaltyPoints);
  cost -= discount;

  return Math.round(cost);
}