﻿using System;
using System.Collections.Concurrent;
using System.Linq;
using System.Threading;

namespace dk.nita.saml20.Session
{
    /// <summary>
    /// Stores sessions in process memory. Expired sessions and user associations are automatically cleaned up
    /// </summary>
    public class InProcSessionStoreProvider : ISessionStoreProvider
    {
        class Session
        {
            internal DateTime Timestamp { get; private set; }
            internal ConcurrentDictionary<string, object> Properties { get; }

            public Session()
            {
                Timestamp = DateTime.UtcNow;
                Properties = new ConcurrentDictionary<string, object>();
            }

            internal void UpdateTimestamp()
            {
                Timestamp = DateTime.UtcNow;
            }
        }

        readonly ConcurrentDictionary<Guid, Session> _sessions = new ConcurrentDictionary<Guid, Session>();
        readonly ConcurrentDictionary<Guid, string> _userAssociations = new ConcurrentDictionary<Guid, string>();
        private TimeSpan _sessionTimeout;
        private Timer _cleanupTimer;

        /// <summary>
        /// 
        /// </summary>
        public InProcSessionStoreProvider()
        {
            // Starting job for cleaning up the cache.
            _cleanupTimer = new Timer(Cleanup, null, TimeSpan.Zero, Timeout.InfiniteTimeSpan);
        }

        private void Cleanup(object state)
        {
            try
            {
                foreach (var s in _sessions)
                {
                    if (s.Value.Timestamp + _sessionTimeout < DateTime.UtcNow)
                    {
                        Session d;
                        _sessions.TryRemove(s.Key, out d);
                    }
                }

                foreach (var ua in _userAssociations)
                {
                    // Also remove the user association if the associated session does not exists anymore.
                    if (!_sessions.ContainsKey(ua.Key))
                    {
                        string d;
                        _userAssociations.TryRemove(ua.Key, out d);
                    }
                }
            }
            finally
            {
                _cleanupTimer.Change(TimeSpan.FromSeconds(10), Timeout.InfiniteTimeSpan);
            }
        }

        void ISessionStoreProvider.SetSessionProperty(Guid sessionId, string key, object value)
        {
            var session = _sessions.GetOrAdd(sessionId, new Session());
            session.UpdateTimestamp();
            session.Properties.AddOrUpdate(key, value, (k,e) => value);
        }

        void ISessionStoreProvider.RemoveSessionProperty(Guid sessionId, string key)
        {
            Session session;
            if (_sessions.TryGetValue(sessionId, out session))
            {
                session.UpdateTimestamp();

                object val;
                session.Properties.TryRemove(key, out val);
            }
        }

        object ISessionStoreProvider.GetSessionProperty(Guid sessionId, string key)
        {
            Session session;
            if (_sessions.TryGetValue(sessionId, out session))
            {
                session.UpdateTimestamp();

                object val;
                if (session.Properties.TryGetValue(key, out val))
                {
                    return val;
                }
            }

            return null;
        }

        void ISessionStoreProvider.AssociateUserIdWithSessionId(string userId, Guid sessionId)
        {
            _userAssociations.AddOrUpdate(sessionId, userId, (k, e) => userId);
        }

        void ISessionStoreProvider.AbandonSessionsAssociatedWithUserId(string userId)
        {
            var sessions = _userAssociations
                .Where(x => x.Value == userId)
                .Select(x => x.Key)
                .ToList();

            foreach (var s in sessions)
            {
                Session val;
                _sessions.TryRemove(s, out val);
                string user;
                _userAssociations.TryRemove(s, out user);
            }
        }

        bool ISessionStoreProvider.DoesSessionExists(Guid sessionId)
        {
            Session session;
            if (_sessions.TryGetValue(sessionId, out session) && session.Properties.Any())
            {
                session.UpdateTimestamp();
                return true;
            }

            return false;
        }

        void ISessionStoreProvider.Initialize(TimeSpan sessionTimeout, ISessionValueFactory sessionValueFactory)
        {
            _sessionTimeout = sessionTimeout;
        }
    }
}