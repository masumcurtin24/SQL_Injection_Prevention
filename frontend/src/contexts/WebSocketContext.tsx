// File: frontend/src/contexts/WebSocketContext.tsx

import React, { useEffect, useRef, useState } from 'react';
import { useAppStore } from '../store/appStore';
import type { LiveEvent } from '../types/api';
import { useNotification } from './useNotification';
import {
    API_BASE_URL,
    clearAuthSession,
    getAccessToken,
    getAuthUser,
    getLiveEvents,
    getSelectedTenantId,
    getStepUpTokenForAction,
} from '../lib/apiClient';
import { WebSocketContext } from './webSocketContextBase';
import type { WSStatus } from './webSocketContextBase';

const ADMIN_ROLES = new Set(['admin', 'analyst']);
const USER_EVENT_TYPES = 'query,file_scan,spam_check';
const ADMIN_EVENT_TYPES = 'query,file_scan,spam_check,alert';
const WS_APPLICATION_SUBPROTOCOL = 'sqliprev.v1';
const WS_ACCESS_TOKEN_SUBPROTOCOL_PREFIX = 'sqliprev.access.';
const WS_STEP_UP_TOKEN_SUBPROTOCOL_PREFIX = 'sqliprev.stepup.';

type LiveFeedScope = {
    isAdmin: boolean;
    eventTypes: string;
    day?: string;
};

const getLiveFeedScope = (): LiveFeedScope => {
    const role = String(getAuthUser()?.role || 'viewer').toLowerCase();
    const isAdmin = ADMIN_ROLES.has(role);
    if (isAdmin) {
        return { isAdmin: true, eventTypes: ADMIN_EVENT_TYPES };
    }
    return {
        isAdmin: false,
        eventTypes: USER_EVENT_TYPES,
        day: new Date().toISOString().slice(0, 10),
    };
};

export const WebSocketProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
    const ws = useRef<WebSocket | null>(null);
    const [status, setStatus] = useState<WSStatus>('disconnected');
    const {
        addLiveEvent,
        setLiveEvents,
        setLiveFeedMeta,
        incrementQueries,
        incrementMaliciousQueries,
        incrementFilesScanned,
        incrementSpamDetected,
    } = useAppStore();
    
    const fetchInitialEvents = async () => {
        try {
            const scope = getLiveFeedScope();
            const tenantId = getSelectedTenantId() || undefined;
            const res = await getLiveEvents(200, {
                day: scope.day,
                event_types: scope.eventTypes,
                tenant_id: tenantId,
            });
            const events = (res.data?.events || []).map((e: any) => ({
                id: String(e.id || Date.now()),
                type: e.type,
                tenant_id: e.tenant_id ? String(e.tenant_id) : null,
                message: String(e.message || ''),
                timestamp: String(e.timestamp || new Date().toISOString()),
                isMalicious: Boolean(e.isMalicious),
            }));
            setLiveEvents(events);
            setLiveFeedMeta({
                scope: res.data?.scope,
                day: res.data?.day ?? null,
                before: res.data?.before ?? null,
                event_types: res.data?.event_types,
                next_before: res.data?.next_before ?? null,
                has_more: Boolean(res.data?.has_more),
                limit: Number(res.data?.limit || 200),
            });
        } catch (err) {
            console.warn('Failed to load initial live events', err);
            setLiveFeedMeta(null);
        }
    };
    const { showNotification } = useNotification();

    useEffect(() => {
        const buildTargets = () => {
            const token = getAccessToken();
            if (!token) return [];
            const scope = getLiveFeedScope();
            let effectiveEventTypes = scope.eventTypes;
            let stepUpToken = '';
            const tenantId = getSelectedTenantId();
            if (scope.isAdmin) {
                const wsStepUp = getStepUpTokenForAction('ws.alert.subscribe');
                if (wsStepUp) {
                    stepUpToken = wsStepUp;
                } else {
                    // Fall back to non-alert stream until step-up is available.
                    effectiveEventTypes = USER_EVENT_TYPES;
                }
            }
            const params = new URLSearchParams();
            params.set('event_types', effectiveEventTypes);
            if (tenantId) params.set('tenant_id', tenantId);
            const encodedQuery = params.toString();
            const protocols = [
                WS_APPLICATION_SUBPROTOCOL,
                `${WS_ACCESS_TOKEN_SUBPROTOCOL_PREFIX}${token}`,
            ];
            if (stepUpToken) {
                protocols.push(`${WS_STEP_UP_TOKEN_SUBPROTOCOL_PREFIX}${stepUpToken}`);
            }
            try {
                const resolvedApiBase = /^https?:\/\//i.test(API_BASE_URL)
                    ? API_BASE_URL
                    : `${window.location.origin}${API_BASE_URL.startsWith('/') ? '' : '/'}${API_BASE_URL}`;
                const apiUrl = new URL(resolvedApiBase);
                const wsProtocol = apiUrl.protocol === 'https:' ? 'wss:' : 'ws:';
                const wsPath = apiUrl.pathname.replace(/\/+$/, '');
                return [{
                    url: `${wsProtocol}//${apiUrl.host}${wsPath}/ws/updates?${encodedQuery}`,
                    protocols,
                }];
            } catch {
                return [{
                    url: `ws://localhost:8000/api/v1/ws/updates?${encodedQuery}`,
                    protocols,
                }];
            }
        };
        let targets = buildTargets();
        let urlIndex = 0;
        let reconnectAttempts = 0;
        let shouldReconnect = true;
        const nextDelay = () => Math.min(30000, 1000 * Math.pow(2, reconnectAttempts));
        const connect = () => {
            if (!shouldReconnect) return;
            targets = buildTargets();
            if (targets.length === 0) {
                setStatus('disconnected');
                return;
            }
            try {
                const target = targets[urlIndex];
                ws.current = new WebSocket(target.url, target.protocols);
                setStatus('connecting');
            } catch {
                // Schedule reconnect using backoff.
                urlIndex = (urlIndex + 1) % targets.length;
                reconnectAttempts += 1;
                setTimeout(connect, nextDelay());
                return;
            }

            ws.current.onopen = () => {
                console.log('WebSocket Connected');
                reconnectAttempts = 0; // reset backoff
                showNotification('Real-time connection established.', 'info');
                setStatus('connected');
            };

            ws.current.onmessage = (event) => {
                try {
                    const raw = JSON.parse(event.data);
                    if (!raw || typeof raw !== 'object') return;
                    if (raw.type === 'ws.auth.notice') {
                        showNotification('Live alert stream requires step-up authentication.', 'info');
                        return;
                    }
                    if (raw.type === 'ws.session') {
                        return;
                    }

                    // Convert backend broadcast into LiveEvent shape when possible
                    if (raw.type && ['query','file_scan','spam_check','alert','NEW_ALERT_DETAILS'].includes(raw.type)) {
                        const scope = getLiveFeedScope();
                        const normalizedType = raw.type === 'NEW_ALERT_DETAILS' ? 'alert' : raw.type;
                        if (!scope.isAdmin && normalizedType === 'alert') {
                            return;
                        }
                        let derived: Partial<LiveEvent> = {};
                        if (raw.type === 'NEW_ALERT_DETAILS' && raw.alert) {
                            const a = raw.alert;
                            derived = {
                                id: String(a.id || Date.now()),
                                type: 'alert',
                                message: String(a.title || a.message || 'New alert'),
                                timestamp: String(a.timestamp || new Date().toISOString()),
                                isMalicious: String(a.severity || '').toLowerCase() === 'high',
                            };
                        }
                        const live: LiveEvent = {
                            id: String(raw.id || derived.id || Date.now()),
                            type: (raw.type === 'NEW_ALERT_DETAILS' ? 'alert' : raw.type) as any,
                            tenant_id: raw?.tenant_id ? String(raw.tenant_id) : null,
                            message: String(raw.message || derived.message || ''),
                            timestamp: String(raw.timestamp || derived.timestamp || new Date().toISOString()),
                            isMalicious: Boolean(raw.isMalicious ?? derived.isMalicious),
                        };
                        addLiveEvent(live);

                        // Update counters
                        if (live.type === 'query') {
                            incrementQueries();
                            if (live.isMalicious) {
                                incrementMaliciousQueries();
                                showNotification(`Malicious query detected`, 'error');
                            }
                        } else if (live.type === 'file_scan') {
                            incrementFilesScanned();
                            if (live.isMalicious) {
                                showNotification(`Malicious file detected`, 'warning');
                            }
                        } else if (live.type === 'spam_check') {
                            if (live.isMalicious) {
                                incrementSpamDetected();
                                showNotification(live.message || 'Spam/phishing event flagged', 'info');
                            }
                        }

                        // Broadcast an alert update signal so alert views can refresh
                        if (live.type === 'alert') {
                            try {
                                const ev = new CustomEvent('alerts:new', { detail: raw });
                                window.dispatchEvent(ev);
                            } catch {}
                            // Surface a brief toast for every alert broadcast
                            try { showNotification('New alert available', 'info'); } catch {}
                        }
                    }
                } catch {
                    console.error('Failed to parse WebSocket message:', event.data);
                }
            };

            ws.current.onclose = (event) => {
                console.log('WebSocket Disconnected. Attempting to reconnect...', event.reason);
                if (!shouldReconnect) return;
                if (event.code === 1008) {
                    // Policy violation (invalid/expired/missing token). Wait for auth state change.
                    clearAuthSession();
                    setStatus('disconnected');
                    return;
                }
                if (reconnectAttempts === 0) {
                    showNotification('Real-time connection lost. Reconnecting...', 'error');
                }
                // Cycle URL index (list usually has one canonical URL).
                urlIndex = (urlIndex + 1) % targets.length;
                reconnectAttempts += 1;
                setTimeout(connect, nextDelay());
                setStatus('disconnected');
            };

            ws.current.onerror = (error) => {
                console.error('WebSocket Error:', error);
                try { ws.current?.close(); } catch {}
                setStatus('disconnected');
            };
        };

        if (getAccessToken()) {
            fetchInitialEvents();
            connect();
        } else {
            setStatus('disconnected');
            setLiveEvents([]);
            setLiveFeedMeta(null);
        }

        const onAuthChanged = () => {
            reconnectAttempts = 0;
            urlIndex = 0;
            try { ws.current?.close(); } catch {}
            if (getAccessToken()) {
                fetchInitialEvents();
                connect();
            } else {
                setStatus('disconnected');
                setLiveEvents([]);
                setLiveFeedMeta(null);
            }
        };
        const onStepUpChanged = () => {
            reconnectAttempts = 0;
            urlIndex = 0;
            try { ws.current?.close(); } catch {}
            if (getAccessToken()) {
                connect();
            }
        };
        const onTenantChanged = () => {
            reconnectAttempts = 0;
            urlIndex = 0;
            try { ws.current?.close(); } catch {}
            if (getAccessToken()) {
                fetchInitialEvents();
                connect();
            } else {
                setStatus('disconnected');
                setLiveEvents([]);
                setLiveFeedMeta(null);
            }
        };
        window.addEventListener('auth:changed', onAuthChanged);
        window.addEventListener('stepup:changed', onStepUpChanged);
        window.addEventListener('tenant:changed', onTenantChanged);

        return () => {
            shouldReconnect = false;
            window.removeEventListener('auth:changed', onAuthChanged);
            window.removeEventListener('stepup:changed', onStepUpChanged);
            window.removeEventListener('tenant:changed', onTenantChanged);
            try { ws.current?.close(); } catch {}
            setStatus('disconnected');
        };
    // eslint-disable-next-line react-hooks/exhaustive-deps
    }, []); // Empty dependency array ensures this runs only once on mount

    return (
        <WebSocketContext.Provider value={{ status }}>
            {children}
        </WebSocketContext.Provider>
    );
};
