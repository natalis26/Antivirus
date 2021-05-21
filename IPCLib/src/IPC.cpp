#include "IPC.h"
#include "IPCMailslot.h"



std::shared_ptr<IPCMailslot> IPC::Mailslots(const std::u16string& readPath, const std::u16string& writePath)
{
	return std::make_shared<IPCMailslot>(readPath, writePath);
}
