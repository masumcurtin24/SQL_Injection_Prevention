// File: frontend/src/lib/dateUtils.ts

import { format } from 'date-fns';

/**
 * Formats an ISO 8601 UTC timestamp into a readable local time format.
 * @param timestamp - The ISO string from the backend (e.g., "2023-10-27T10:00:00.000Z").
 * @returns A formatted string like "Oct 27, 2023, 6:00:00 PM".
 */
export const formatTimestamp = (timestamp: string | Date): string => {
  if (!timestamp) return 'N/A';
  try {
    const toDate = (t: string | Date): Date => {
      if (t instanceof Date) return t;
      const s = t.trim();
      // If the ISO string lacks timezone info, assume UTC to avoid local misinterpretation
      const hasTZ = /[zZ]$|[+-]\d{2}:?\d{2}$/.test(s);
      return new Date(hasTZ ? s : `${s}Z`);
    };

    const date = toDate(timestamp);
    // Format as local time
    const main = format(date, 'MMM dd, yyyy, h:mm:ss a');
    // Append numeric UTC offset (e.g., UTC-07:00) for clarity
    const offsetMin = date.getTimezoneOffset(); // minutes behind UTC
    const sign = offsetMin > 0 ? '-' : '+';
    const abs = Math.abs(offsetMin);
    const hh = String(Math.floor(abs / 60)).padStart(2, '0');
    const mm = String(abs % 60).padStart(2, '0');
    const tz = `UTC${sign}${hh}:${mm}`;
    return `${main} (${tz})`;
  } catch (error) {
    console.error('Error formatting date:', error);
    return typeof timestamp === 'string' ? timestamp : 'N/A';
  }
};

