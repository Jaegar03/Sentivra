"use client";

import useSWR, { type SWRConfiguration } from "swr";

import { fetcher } from "@/lib/api";

/**
 * GET an API path with SWR. `keepPreviousData` holds the last render while a
 * refetch is in flight, so charts don't flash or jump on refresh.
 */
export function useApi<T>(path: string | null, config?: SWRConfiguration<T>) {
  return useSWR<T>(path, fetcher<T>, {
    keepPreviousData: true,
    revalidateOnFocus: false,
    ...config,
  });
}
