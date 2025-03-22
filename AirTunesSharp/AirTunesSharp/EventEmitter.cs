using System;
using System.Collections.Generic;

namespace AirTunesSharp
{
    /// <summary>
    /// Interface for implementing event emitter pattern similar to Node.js
    /// </summary>
    public interface IEventEmitter
    {
        void On(string eventName, Action<object[]> listener);
        void Once(string eventName, Action<object[]> listener);
        void RemoveListener(string eventName, Action<object[]> listener);
        void RemoveAllListeners(string? eventName = null);
        void Emit(string eventName, params object[] args);
    }

    /// <summary>
    /// Base implementation of the EventEmitter pattern
    /// </summary>
    public class EventEmitter : IEventEmitter
    {
        private readonly Dictionary<string, List<Action<object[]>>> _events = new();
        private readonly Dictionary<string, List<Action<object[]>>> _onceEvents = new();

        public void On(string eventName, Action<object[]> listener)
        {
            if (!_events.ContainsKey(eventName))
            {
                _events[eventName] = new List<Action<object[]>>();
            }
            _events[eventName].Add(listener);
        }

        public void Once(string eventName, Action<object[]> listener)
        {
            if (!_onceEvents.ContainsKey(eventName))
            {
                _onceEvents[eventName] = new List<Action<object[]>>();
            }
            _onceEvents[eventName].Add(listener);
        }

        public void RemoveListener(string eventName, Action<object[]> listener)
        {
            if (_events.ContainsKey(eventName))
            {
                _events[eventName].Remove(listener);
            }
            
            if (_onceEvents.ContainsKey(eventName))
            {
                _onceEvents[eventName].Remove(listener);
            }
        }

        public void RemoveAllListeners(string? eventName = null)
        {
            if (eventName == null)
            {
                _events.Clear();
                _onceEvents.Clear();
            }
            else
            {
                if (_events.ContainsKey(eventName))
                {
                    _events.Remove(eventName);
                }
                
                if (_onceEvents.ContainsKey(eventName))
                {
                    _onceEvents.Remove(eventName);
                }
            }
        }

        public void Emit(string eventName, params object[] args)
        {
            if (_events.ContainsKey(eventName))
            {
                foreach (var listener in _events[eventName])
                {
                    listener(args);
                }
            }

            if (_onceEvents.ContainsKey(eventName))
            {
                var listeners = _onceEvents[eventName].ToList();
                _onceEvents.Remove(eventName);
                
                foreach (var listener in listeners)
                {
                    listener(args);
                }
            }
        }
    }
}
