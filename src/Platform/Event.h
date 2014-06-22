/*
 Copyright (c) 2008-2009 TrueCrypt Developers Association. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

#ifndef TC_HEADER_Platform_Event
#define TC_HEADER_Platform_Event

#include "PlatformBase.h"
#include "ForEach.h"
#include "Mutex.h"
#include "SharedPtr.h"

namespace VeraCrypt
{
	struct EventArgs
	{
		virtual ~EventArgs () { }
	};

	class EventConnectorBase
	{
	public:
		virtual ~EventConnectorBase () { }
		virtual void operator() (EventArgs &args) = 0;

		virtual EventConnectorBase *CloneNew () const = 0;
		virtual void *GetHandler () const = 0;
	};

	typedef list < shared_ptr <EventConnectorBase> > EventHandlerList;

	template <class T>
	class EventConnector : public EventConnectorBase
	{
	public:
		typedef void (T::*EventHandlerFunction) (EventArgs &);

		EventConnector (T *handler, EventHandlerFunction function)
			: Handler (handler), Function (function) { }

		virtual void operator() (EventArgs &args) { (Handler->*Function) (args); }

		virtual EventConnectorBase *CloneNew () const { return new EventConnector <T> (*this); }
		virtual void *GetHandler () const { return Handler; }

	protected:
		T *Handler;
		EventHandlerFunction Function;
	};

	class Event
	{
	public:
		Event () { }
		virtual ~Event () { }

		void Connect (const EventConnectorBase &connector);
		void Disconnect (void *handler);
		void Raise ();
		void Raise (EventArgs &args);

	protected:
		EventHandlerList ConnectedHandlers;
		Mutex HandlersMutex;

	private:
		Event (const Event &);
		Event &operator= (const Event &);
	};

	struct ExceptionEventArgs : public EventArgs
	{
		ExceptionEventArgs (exception &ex) : mException (ex) { }
		exception &mException;

	private:
		ExceptionEventArgs (const ExceptionEventArgs &);
		ExceptionEventArgs &operator= (const ExceptionEventArgs &);
	};
}

#endif // TC_HEADER_Platform_Event
