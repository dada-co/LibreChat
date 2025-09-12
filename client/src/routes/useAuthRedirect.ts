import { useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuthContext } from '~/hooks';
import { logger } from '~/utils';

export default function useAuthRedirect() {
  const { user, isAuthenticated } = useAuthContext();
  const navigate = useNavigate();

  useEffect(() => {
    const timeout = setTimeout(() => {
      const { pathname, search } = window.location;
      logger.debug('auth', 'useAuthRedirect effect', { pathname, search, isAuthenticated });
      console.log('useAuthRedirect', { pathname, search, isAuthenticated });
      if (!isAuthenticated) {
        logger.warn('auth', `Redirecting to login from ${pathname}${search}`);
        console.log('useAuthRedirect redirect', { pathname, search });
        navigate('/login', { replace: true });
      }
    }, 300);

    return () => {
      clearTimeout(timeout);
    };
  }, [isAuthenticated, navigate]);

  return {
    user,
    isAuthenticated,
  };
}
