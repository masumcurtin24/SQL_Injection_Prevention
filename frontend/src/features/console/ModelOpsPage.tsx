import * as React from 'react';
import {
  getDefenderModels,
  getDefenderStatus,
  getDefenderTrainingJobs,
  getSpamAutopipelineStatus,
} from '../../lib/apiClient';
import { ActionButton, Surface, StatTile, StatusPill, EmptyState, ErrorState, LoadingState } from '../../components/common/ConsoleSurface';
import type {
  DefenderModelInfo,
  DefenderStatusResponse,
  DefenderTrainingJobInfo,
  SpamAutopipelineStatusResponse,
} from '../../types/api';
import { formatTimestamp } from '../../lib/dateUtils';

const ModelOpsPage = ({ role }: { role: string }) => {
  const privileged = role === 'reviewer' || role === 'analyst' || role === 'admin';
  const [loading, setLoading] = React.useState(false);
  const [errorText, setErrorText] = React.useState('');
  const [status, setStatus] = React.useState<DefenderStatusResponse | null>(null);
  const [models, setModels] = React.useState<DefenderModelInfo[]>([]);
  const [jobs, setJobs] = React.useState<DefenderTrainingJobInfo[]>([]);
  const [autopipeline, setAutopipeline] = React.useState<SpamAutopipelineStatusResponse | null>(null);

  const loadModelOps = React.useCallback(async () => {
    if (!privileged) return;
    setLoading(true);
    setErrorText('');
    try {
      const [statusRes, modelsRes, jobsRes, autopipelineRes] = await Promise.all([
        getDefenderStatus(),
        getDefenderModels({ limit: 30 }),
        getDefenderTrainingJobs({ limit: 30 }),
        getSpamAutopipelineStatus(),
      ]);
      setStatus(statusRes.data || null);
      setModels(modelsRes.data || []);
      setJobs(jobsRes.data || []);
      setAutopipeline(autopipelineRes.data || null);
    } catch (error: any) {
      setErrorText(String(error?.response?.data?.detail || 'Failed to load model operations data.'));
    } finally {
      setLoading(false);
    }
  }, [privileged]);

  React.useEffect(() => {
    void loadModelOps();
    if (!privileged) return;
    const timerId = window.setInterval(() => {
      void loadModelOps();
    }, 30000);
    return () => window.clearInterval(timerId);
  }, [loadModelOps, privileged]);

  if (!privileged) {
    return <EmptyState title="Model operations restricted" description="Viewer users do not have access to model status, training jobs, or feedback backlogs." />;
  }

  const activeModels = models.filter((model) => String(model.stage || '').toLowerCase() === 'active').length;
  const failedJobs = jobs.filter((job) => String(job.status || '').toLowerCase() === 'failed').length;

  return (
    <div className="space-y-6">
      {errorText ? (
        <ErrorState message={errorText} onRetry={() => void loadModelOps()} />
      ) : null}

      {loading && !status ? (
        <LoadingState label="Loading model registry and training operations..." />
      ) : null}

      {!loading && !status ? (
        <EmptyState title="No model operations snapshot" description="Model lifecycle telemetry is not available yet." />
      ) : null}

      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-6">
        <StatTile label="Pending feedback" value={status?.pending_feedback ?? '-'} tone="warning" meta="Samples awaiting review" />
        <StatTile label="SQL feedback" value={status?.feedback_counts?.sql ?? '-'} tone="info" meta="Human labels collected" />
        <StatTile label="File feedback" value={status?.feedback_counts?.file ?? '-'} tone="info" meta="Human labels collected" />
        <StatTile label="Spam feedback" value={status?.feedback_counts?.spam ?? '-'} tone="info" meta="Human labels collected" />
        <StatTile label="Active models" value={activeModels} tone={activeModels >= 3 ? 'success' : 'warning'} meta="Registry stage=active" />
        <StatTile label="Failed jobs" value={failedJobs} tone={failedJobs > 0 ? 'danger' : 'success'} meta="Recent retraining jobs" />
      </div>

      <div className="grid gap-6 xl:grid-cols-[1fr_1fr]">
        <Surface
          title="Model registry"
          description="Current model stages and domains in the defender registry."
          actions={
            <ActionButton
              onClick={() => void loadModelOps()}
              disabled={loading}
              variant="primary"
            >
              {loading ? 'Refreshing...' : 'Refresh'}
            </ActionButton>
          }
        >
          <div className="space-y-3">
            {models.length === 0 ? (
              <EmptyState title="No model registry entries" description="Train or register a model candidate to populate registry history." />
            ) : (
              models.map((model) => (
                <div key={model.id} className="rounded-2xl border border-border-dark/70 bg-dark-tertiary/70 p-4">
                  <div className="flex flex-wrap items-center justify-between gap-3">
                    <div>
                      <p className="text-sm font-semibold text-white">{model.domain.toUpperCase()} - {model.version}</p>
                      <p className="mt-1 text-xs text-text-secondary">Model id {model.id}</p>
                    </div>
                    <StatusPill label={model.stage} tone={model.stage === 'active' ? 'success' : model.stage === 'candidate' ? 'warning' : 'neutral'} />
                  </div>
                  <p className="mt-2 text-xs text-text-secondary">Created {formatTimestamp(model.created_at || '')}</p>
                </div>
              ))
            )}
          </div>
        </Surface>

        <Surface title="Training jobs" description="Recent defender retraining activity and execution state.">
          <div className="space-y-3">
            {jobs.length === 0 ? (
              <EmptyState title="No training jobs" description="Start a defender training run to capture lifecycle and gate outcomes here." />
            ) : (
              jobs.map((job) => (
                <div key={job.id} className="rounded-2xl border border-border-dark/70 bg-dark-tertiary/70 p-4">
                  <div className="flex flex-wrap items-center justify-between gap-3">
                    <div>
                      <p className="text-sm font-semibold text-white">{job.domain.toUpperCase()} retrain</p>
                      <p className="mt-1 text-xs text-text-secondary">Job {job.id}</p>
                    </div>
                    <StatusPill
                      label={job.status}
                      tone={
                        String(job.status || '').toLowerCase() === 'completed' ||
                        String(job.status || '').toLowerCase() === 'succeeded'
                          ? 'success'
                          : String(job.status || '').toLowerCase() === 'failed'
                            ? 'danger'
                            : 'warning'
                      }
                    />
                  </div>
                  <p className="mt-2 text-xs text-text-secondary">Created {formatTimestamp(job.created_at || '')}</p>
                  {job.completed_at ? <p className="mt-1 text-xs text-text-secondary">Completed {formatTimestamp(job.completed_at)}</p> : null}
                </div>
              ))
            )}
          </div>
        </Surface>
      </div>

      <Surface title="Spam autopipeline scheduler" description="Automated spam retraining cadence and scheduler health.">
        {autopipeline ? (
          <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
            <div className="rounded-2xl border border-border-dark/70 bg-dark-tertiary/70 p-4">
              <p className="text-xs uppercase tracking-[0.14em] text-text-secondary">Enabled</p>
              <div className="mt-3"><StatusPill label={autopipeline.enabled ? 'Enabled' : 'Disabled'} tone={autopipeline.enabled ? 'success' : 'warning'} /></div>
            </div>
            <div className="rounded-2xl border border-border-dark/70 bg-dark-tertiary/70 p-4">
              <p className="text-xs uppercase tracking-[0.14em] text-text-secondary">Interval</p>
              <p className="mt-3 text-2xl font-semibold text-white">{autopipeline.interval_minutes}m</p>
            </div>
            <div className="rounded-2xl border border-border-dark/70 bg-dark-tertiary/70 p-4">
              <p className="text-xs uppercase tracking-[0.14em] text-text-secondary">Runs</p>
              <p className="mt-3 text-2xl font-semibold text-white">{autopipeline.runs_total}</p>
              <p className="mt-1 text-xs text-text-secondary">Success {autopipeline.runs_succeeded} / Failed {autopipeline.runs_failed}</p>
            </div>
            <div className="rounded-2xl border border-border-dark/70 bg-dark-tertiary/70 p-4">
              <p className="text-xs uppercase tracking-[0.14em] text-text-secondary">Current state</p>
              <div className="mt-3"><StatusPill label={autopipeline.in_progress ? 'Running' : 'Idle'} tone={autopipeline.in_progress ? 'warning' : 'success'} /></div>
            </div>
          </div>
        ) : (
          <p className="text-sm text-text-secondary">Autopipeline status unavailable.</p>
        )}
      </Surface>
    </div>
  );
};

export default ModelOpsPage;
