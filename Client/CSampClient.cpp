#include <SAMP+/client/CSampClient.h>
#include <SAMP+/client/CLog.h>

namespace
{
	const SampClient::Layout kLayouts[] =
	{
		{ SampClient::VERSION_037_R1, "0.3.7-R1", 0x31DF13, 0x21A0F8, 0x3C9, 0x21A0E8, 0x3CD, 0x1C, 0x1134, 0x4C },
		{ SampClient::VERSION_037_R31, "0.3.7-R3-1", 0xCC4D0, 0x26E8DC, 0x2C, 0x26E8CC, 0x3DE, 0x0C, 0x1134, 0x4C },
		{ SampClient::VERSION_037_R4, "0.3.7-R4", 0xCBCB0, 0x26EA0C, 0x2C, 0x26E9FC, 0x3DE, 0x0C, 0x1134, 0x4C },
		{ SampClient::VERSION_03DL_R1, "0.3DL-R1", 0xFDB60, 0x2ACA24, 0x2C, 0x2ACA14, 0x3DE, 0x0C, 0x1134, 0x4C },
		// R4-v2/R5 keep the same vehicle-pool layout but the pool pointer
		// moved to the start of the pools object.
		{ SampClient::VERSION_UNKNOWN, "0.3.7-R4-v2", 0, 0x26EA0C, 0, 0x26E9FC, 0x3DE, 0x00, 0x1134, 0x4C },
		{ SampClient::VERSION_UNKNOWN, "0.3.7-R5", 0, 0x26EB94, 0, 0x26EB84, 0x3DE, 0x00, 0x1134, 0x4C }
	};

	const DWORD VehicleListedOffset = 0x3074;
	// Direct CVehicle* (GTA) array in CVehiclePool — same on 0.3.7 and 0.3DL.
	// 0x3074 + 2000*sizeof(DWORD) = 0x4FB4.
	const DWORD VehicleGtaArrayOffset = 0x4FB4;
	const unsigned short MaxSampVehicles = 2000;
	const DWORD VehiclePoolMinSize = VehicleGtaArrayOffset + MaxSampVehicles * sizeof(DWORD);
	DWORD g_lastVehicleResolveLog[MaxSampVehicles] = {};

	void LogVehicleResolveFailure(unsigned short vehicleId, const char* stage, DWORD base, DWORD entryPoint, DWORD sampInfo, DWORD pools, DWORD vehiclePool, DWORD sampVehicle, DWORD gtaVehicle)
	{
		if (vehicleId >= MaxSampVehicles)
			return;

		DWORD now = GetTickCount();
		if (g_lastVehicleResolveLog[vehicleId] && now - g_lastVehicleResolveLog[vehicleId] < 2000)
			return;

		g_lastVehicleResolveLog[vehicleId] = now;
		CLog::Write("Wheel resolve failed: vehicle=%u stage=%s base=0x%08X ep=0x%08X sampInfo=0x%08X pools=0x%08X vehiclePool=0x%08X sampVehicle=0x%08X gtaVehicle=0x%08X",
			vehicleId, stage, base, entryPoint, sampInfo, pools, vehiclePool, sampVehicle, gtaVehicle);
	}

	bool IsReadableProtection(DWORD protect)
	{
		if (protect & (PAGE_NOACCESS | PAGE_GUARD))
			return false;

		switch (protect & 0xFF)
		{
		case PAGE_READONLY:
		case PAGE_READWRITE:
		case PAGE_WRITECOPY:
		case PAGE_EXECUTE_READ:
		case PAGE_EXECUTE_READWRITE:
		case PAGE_EXECUTE_WRITECOPY:
			return true;
		default:
			return false;
		}
	}

	bool IsExecutableProtection(DWORD protect)
	{
		if (protect & (PAGE_NOACCESS | PAGE_GUARD))
			return false;

		switch (protect & 0xFF)
		{
		case PAGE_EXECUTE:
		case PAGE_EXECUTE_READ:
		case PAGE_EXECUTE_READWRITE:
		case PAGE_EXECUTE_WRITECOPY:
			return true;
		default:
			return false;
		}
	}

	bool IsLikelyGtaVehicle(DWORD gtaVehicle)
	{
		if (!SampClient::CanRead(gtaVehicle, 0x20))
			return false;

		DWORD gtaVtable = 0;
		if (!SampClient::ReadPointer(gtaVehicle, gtaVtable) || !SampClient::IsExecutableAddress(gtaVtable))
			return false;

		// CEntity::m_pRwObject / clump pointer. May be null while streaming;
		// still accept the entity if the vtable looks valid.
		return true;
	}

	bool TryResolveWithLayout(const SampClient::Layout& layout, DWORD base, unsigned short vehicleId,
		DWORD& lastSampInfo, DWORD& lastPools, DWORD& lastVehiclePool, DWORD& lastSampVehicle, DWORD& lastGtaVehicle, DWORD& gtaVehicle)
	{
		if (!layout.sampInfoOffset)
			return false;

		DWORD sampInfo = 0, pools = 0, vehiclePool = 0;
		if (!SampClient::ReadPointer(base + layout.sampInfoOffset, sampInfo) || !SampClient::CanRead(sampInfo, 0x400))
			return false;
		lastSampInfo = sampInfo;

		if (!SampClient::ReadPointer(sampInfo + layout.poolsOffset, pools) || !SampClient::CanRead(pools, 0x20))
			return false;
		lastPools = pools;

		// Prefer the documented pool offset, then common alternates used by
		// launcher-patched clients.
		const DWORD poolOffsets[] = { layout.vehiclePoolOffset, 0x00, 0x0C, 0x1C };
		for (size_t p = 0; p < sizeof(poolOffsets) / sizeof(poolOffsets[0]); ++p)
		{
			if (!SampClient::ReadPointer(pools + poolOffsets[p], vehiclePool) || !SampClient::CanRead(vehiclePool, VehiclePoolMinSize))
				continue;
			lastVehiclePool = vehiclePool;

			DWORD listedAddr = vehiclePool + VehicleListedOffset + vehicleId * sizeof(DWORD);
			if (!SampClient::CanRead(listedAddr, sizeof(DWORD)))
				continue;

			DWORD listed = *reinterpret_cast<DWORD*>(listedAddr);
			if (!listed)
				continue;

			// Primary path used by handling mods: direct GTA vehicle pointer array.
			DWORD directGta = 0;
			if (SampClient::ReadPointer(vehiclePool + VehicleGtaArrayOffset + vehicleId * sizeof(DWORD), directGta)
				&& IsLikelyGtaVehicle(directGta))
			{
				lastGtaVehicle = directGta;
				gtaVehicle = directGta;
				return true;
			}

			// Fallback: SA-MP CVehicle wrapper -> embedded GTA entity pointer.
			DWORD sampVehicle = 0;
			if (!SampClient::ReadPointer(vehiclePool + layout.vehicleArrayOffset + vehicleId * sizeof(DWORD), sampVehicle)
				|| !SampClient::CanRead(sampVehicle, layout.vehicleGtaOffset + sizeof(DWORD)))
				continue;
			lastSampVehicle = sampVehicle;

			DWORD wrapperGta = 0;
			if (!SampClient::ReadPointer(sampVehicle + layout.vehicleGtaOffset, wrapperGta) || !IsLikelyGtaVehicle(wrapperGta))
				continue;

			lastGtaVehicle = wrapperGta;
			gtaVehicle = wrapperGta;
			return true;
		}

		return false;
	}
}

namespace SampClient
{
	DWORD GetBase()
	{
		return reinterpret_cast<DWORD>(GetModuleHandleA("samp.dll"));
	}

	bool CanRead(DWORD address, size_t size)
	{
		if (!address || !size)
			return false;

		DWORD cursor = address;
		size_t remaining = size;
		while (remaining > 0)
		{
			MEMORY_BASIC_INFORMATION mbi;
			if (!VirtualQuery(reinterpret_cast<LPCVOID>(cursor), &mbi, sizeof(mbi)))
				return false;

			if (mbi.State != MEM_COMMIT || !IsReadableProtection(mbi.Protect))
				return false;

			DWORD regionEnd = reinterpret_cast<DWORD>(mbi.BaseAddress) + static_cast<DWORD>(mbi.RegionSize);
			if (regionEnd <= cursor)
				return false;

			size_t readable = static_cast<size_t>(regionEnd - cursor);
			if (readable >= remaining)
				return true;

			cursor += static_cast<DWORD>(readable);
			remaining -= readable;
		}

		return true;
	}

	bool ReadPointer(DWORD address, DWORD& value)
	{
		if (!CanRead(address, sizeof(DWORD)))
			return false;

		value = *reinterpret_cast<DWORD*>(address);
		return value != 0;
	}

	bool IsExecutableAddress(DWORD address)
	{
		if (!address)
			return false;

		MEMORY_BASIC_INFORMATION mbi;
		if (!VirtualQuery(reinterpret_cast<LPCVOID>(address), &mbi, sizeof(mbi)))
			return false;

		return mbi.State == MEM_COMMIT && IsExecutableProtection(mbi.Protect);
	}

	bool ValidateVTableObject(DWORD objectAddress, size_t methodCount)
	{
		DWORD vtable = 0;
		if (!ReadPointer(objectAddress, vtable))
			return false;

		if (!CanRead(vtable, methodCount * sizeof(DWORD)))
			return false;

		for (size_t i = 0; i < methodCount; ++i)
		{
			DWORD method = 0;
			if (!ReadPointer(vtable + static_cast<DWORD>(i * sizeof(DWORD)), method))
				return false;
			if (!IsExecutableAddress(method))
				return false;
		}

		return true;
	}

	DWORD GetEntryPoint(DWORD base)
	{
		if (!base || !CanRead(base, sizeof(IMAGE_DOS_HEADER)))
			return 0;

		IMAGE_DOS_HEADER* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
		if (dos->e_magic != IMAGE_DOS_SIGNATURE)
			return 0;

		DWORD ntAddress = base + dos->e_lfanew;
		if (!CanRead(ntAddress, sizeof(IMAGE_NT_HEADERS)))
			return 0;

		IMAGE_NT_HEADERS* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(ntAddress);
		if (nt->Signature != IMAGE_NT_SIGNATURE)
			return 0;

		return nt->OptionalHeader.AddressOfEntryPoint;
	}

	Version GetVersion(DWORD base)
	{
		DWORD entryPoint = GetEntryPoint(base);
		for (size_t i = 0; i < sizeof(kLayouts) / sizeof(kLayouts[0]); ++i)
		{
			if (kLayouts[i].entryPoint == entryPoint)
				return kLayouts[i].version;
		}

		return VERSION_UNKNOWN;
	}

	const char* GetVersionName(Version version)
	{
		Layout layout;
		return GetLayout(version, layout) ? layout.name : "unknown";
	}

	bool GetLayout(Version version, Layout& layout)
	{
		if (version == VERSION_UNKNOWN)
			return false;
		for (size_t i = 0; i < sizeof(kLayouts) / sizeof(kLayouts[0]); ++i)
		{
			if (kLayouts[i].version == version)
			{
				layout = kLayouts[i];
				return true;
			}
		}

		return false;
	}

	bool ResolveSampInfo(DWORD& sampInfo)
	{
		DWORD base = GetBase();
		Version version = GetVersion(base);
		Layout layout;
		if (!GetLayout(version, layout))
			return false;

		return ReadPointer(base + layout.sampInfoOffset, sampInfo);
	}

	bool ResolveVehicle(unsigned short vehicleId, DWORD& gtaVehicle)
	{
		gtaVehicle = 0;
		if (vehicleId >= MaxSampVehicles)
			return false;

		DWORD base = GetBase();
		DWORD entryPoint = GetEntryPoint(base);
		DWORD lastSampInfo = 0;
		DWORD lastPools = 0;
		DWORD lastVehiclePool = 0;
		DWORD lastSampVehicle = 0;
		DWORD lastGtaVehicle = 0;
		const char* stage = "samp.dll";
		if (!base)
		{
			LogVehicleResolveFailure(vehicleId, stage, base, entryPoint, lastSampInfo, lastPools, lastVehiclePool, lastSampVehicle, lastGtaVehicle);
			return false;
		}

		Version version = GetVersion(base);
		const size_t layoutCount = sizeof(kLayouts) / sizeof(kLayouts[0]);

		// Prefer the entry-point layout. If its pool chain is valid but the
		// vehicle is not streamed yet, do not fall through to wrong versions.
		if (version != VERSION_UNKNOWN)
		{
			Layout detected;
			if (GetLayout(version, detected))
			{
				stage = detected.name;
				if (TryResolveWithLayout(detected, base, vehicleId, lastSampInfo, lastPools, lastVehiclePool, lastSampVehicle, lastGtaVehicle, gtaVehicle))
					return true;

				if (lastVehiclePool)
				{
					LogVehicleResolveFailure(vehicleId, stage, base, entryPoint, lastSampInfo, lastPools, lastVehiclePool, lastSampVehicle, lastGtaVehicle);
					return false;
				}
			}
		}

		for (size_t i = 0; i < layoutCount; ++i)
		{
			if (version != VERSION_UNKNOWN && kLayouts[i].version == version)
				continue;

			stage = kLayouts[i].name;
			if (TryResolveWithLayout(kLayouts[i], base, vehicleId, lastSampInfo, lastPools, lastVehiclePool, lastSampVehicle, lastGtaVehicle, gtaVehicle))
				return true;

			if (lastVehiclePool)
				break;
		}

		LogVehicleResolveFailure(vehicleId, stage, base, entryPoint, lastSampInfo, lastPools, lastVehiclePool, lastSampVehicle, lastGtaVehicle);
		return false;
	}

	bool IsChatInputActive()
	{
		DWORD base = GetBase();
		Version version = GetVersion(base);
		Layout layout;
		if (!GetLayout(version, layout))
			return false;

		DWORD inputInfo = 0;
		if (!ReadPointer(base + layout.chatInputInfoOffset, inputInfo))
			return false;

		DWORD editBox = 0;
		if (!ReadPointer(inputInfo + 0x8, editBox))
			return false;

		if (!CanRead(editBox + 0x4, sizeof(unsigned char)))
			return false;

		return *reinterpret_cast<unsigned char*>(editBox + 0x4) != 0;
	}
}
