import { useEffect, useRef, useState } from 'react';
import { CheckCircle2, XCircle } from 'lucide-react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import type { IntegrationDetail } from '@token-vault/shared';
import { ApiError, api } from '@/lib/api';
import { Button } from '@/components/ui/button';
import { Card, CardBody } from '@/components/ui/card';
import { Spinner } from '@/components/ui/feedback';
import { useToast } from '@/components/ui/toast';

/**
 * Where the OAuth provider sends the admin back. The session cookie is SameSite=Strict, so
 * it is not sent on the provider's cross-site redirect; this page loads without it and then
 * completes the connection with a same-origin request, which does carry the cookie.
 * The code and state are removed from the address bar immediately.
 */
export function OAuthCallbackPage() {
  const [params] = useSearchParams();
  const navigate = useNavigate();
  const toast = useToast();
  const started = useRef(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (started.current) return; // React StrictMode runs effects twice in development
    started.current = true;
    const code = params.get('code');
    const state = params.get('state');
    const providerError = params.get('error');
    window.history.replaceState({}, '', '/oauth/callback'); // keep the single-use code out of history
    (async () => {
      if (!state) return setError('The provider did not return a state. Start again from the integration catalog.');
      if (providerError || !code) {
        await api.post('/integration/oauthCancel', { state }).catch(() => undefined);
        return setError(providerError === 'access_denied' ? 'Access was not granted at the provider.' : `The provider returned an error${providerError ? ` (${providerError})` : ''}.`);
      }
      try {
        const integration = await api.post<IntegrationDetail>('/integration/oauthComplete', { code, state });
        toast.success(`${integration.displayName} connected`, 'The OAuth tokens are encrypted inside your customer webhook.');
        navigate(`/integrations/${integration.id}`, { replace: true });
      } catch (e) {
        setError(e instanceof ApiError ? e.message : 'The connection could not be completed.');
      }
    })();
  }, [params, navigate, toast]);

  return (
    <div className="mx-auto mt-10 max-w-lg">
      <Card>
        <CardBody className="space-y-4 text-center">
          {error ? (
            <>
              <XCircle className="mx-auto h-8 w-8 text-red-600" />
              <p className="font-semibold text-slate-900">Connection not completed</p>
              <p className="text-sm text-slate-600" data-testid="oauth-error">
                {error}
              </p>
              <Button onClick={() => navigate('/integrations/catalog')}>Back to the catalog</Button>
            </>
          ) : (
            <>
              <CheckCircle2 className="mx-auto h-8 w-8 text-slate-300" />
              <p className="font-semibold text-slate-900">Completing the connection…</p>
              <Spinner label="The customer webhook is redeeming the authorization code" />
            </>
          )}
        </CardBody>
      </Card>
    </div>
  );
}
