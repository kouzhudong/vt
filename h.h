#pragma once

#include <ntifs.h>
#include <windef.h>
#include <ntddk.h>

#include <intrin.h> //VS2012编译。
#include <immintrin.h>//VS2012编译。
//#include <mmintrin.h> //WDK 编译。
//#include <emmintrin.h>//WDK 编译。
//#include <xmmintrin.h>//WDK 编译。

#pragma warning(disable : 4201) //使用了非标准扩展: 无名称的结构/联合

#define EXIT_REASON_EXCEPTION_NMI       0
#define EXIT_REASON_EXTERNAL_INTERRUPT  1
#define EXIT_REASON_TRIPLE_FAULT        2
#define EXIT_REASON_INIT                3
#define EXIT_REASON_SIPI                4
#define EXIT_REASON_IO_SMI              5
#define EXIT_REASON_OTHER_SMI           6
#define EXIT_REASON_PENDING_INTERRUPT   7
#define EXIT_REASON_TASK_SWITCH         9
#define EXIT_REASON_CPUID               10
#define EXIT_REASON_HLT                 12
#define EXIT_REASON_INVD                13
#define EXIT_REASON_INVLPG              14
#define EXIT_REASON_RDPMC               15
#define EXIT_REASON_RDTSC               16
#define EXIT_REASON_RSM                 17
#define EXIT_REASON_VMCALL              18
#define EXIT_REASON_VMCLEAR             19
#define EXIT_REASON_VMLAUNCH            20
#define EXIT_REASON_VMPTRLD             21
#define EXIT_REASON_VMPTRST             22
#define EXIT_REASON_VMREAD              23
#define EXIT_REASON_VMRESUME            24
#define EXIT_REASON_VMWRITE             25
#define EXIT_REASON_VMXOFF              26
#define EXIT_REASON_VMXON               27
#define EXIT_REASON_CR_ACCESS           28
#define EXIT_REASON_DR_ACCESS           29
#define EXIT_REASON_IO_INSTRUCTION      30
#define EXIT_REASON_MSR_READ            31
#define EXIT_REASON_MSR_WRITE           32
#define EXIT_REASON_INVALID_GUEST_STATE 33
#define EXIT_REASON_MSR_LOADING         34
#define EXIT_REASON_MWAIT_INSTRUCTION   36
#define EXIT_REASON_MONITOR_INSTRUCTION 39
#define EXIT_REASON_PAUSE_INSTRUCTION   40
#define EXIT_REASON_MACHINE_CHECK       41
#define EXIT_REASON_TPR_BELOW_THRESHOLD 43
#define VMX_MAX_GUEST_VMEXIT	EXIT_REASON_TPR_BELOW_THRESHOLD

#if defined(_WIN64)
#pragma pack (push, 1)
typedef struct _AMD64_DESCRIPTOR {// Special Registers for AMD64.
    USHORT  Pad[3];
    USHORT  Limit;
    ULONG64 Base;
} AMD64_DESCRIPTOR, *PAMD64_DESCRIPTOR;
#pragma pack(pop)
#endif

#pragma pack (push, 1)
typedef union _KGDTENTRY64 {
    struct {
        USHORT  LimitLow;
        USHORT  BaseLow;
        union {
            struct {
                UCHAR   BaseMiddle;
                UCHAR   Flags1;
                UCHAR   Flags2;
                UCHAR   BaseHigh;
            } Bytes;

            struct {
                ULONG   BaseMiddle : 8;
                ULONG   Type : 5;//把S位包含进去了，也就是是否为系统段描述符的位。
                ULONG   Dpl : 2;
                ULONG   Present : 1;
                ULONG   LimitHigh : 4;
                ULONG   System : 1;//即AVL，系统软件自定义的。
                ULONG   LongMode : 1;
                ULONG   DefaultBig : 1;//即INTEL的D/B (default operation size/default stack pointer size and/or upper bound) flag。
                ULONG   Granularity : 1;
                ULONG   BaseHigh : 8;
            } Bits;
        };

        //ULONG BaseUpper;/*经观察，64下的结构的长度是6字节，不是上面定义的16字节。*/
        //ULONG MustBeZero;
    };

    //ULONG64 Alignment;
} KGDTENTRY64, *PKGDTENTRY64;
#pragma pack(pop)

#define CONTROL_REG_ACCESS_NUM          0xf     /* 3:0, number of control register */
#define CONTROL_REG_ACCESS_TYPE         0x30    /* 5:4, access type */
#define CONTROL_REG_ACCESS_REG          0xf00   /* 10:8, general purpose register */

/* XXX these are really VMX specific */
#define TYPE_MOV_TO_CR          (0 << 4)
#define TYPE_MOV_FROM_CR        (1 << 4)

/*
 * Intel CPU flags in CR0
 */
#define X86_CR0_PE              0x00000001      /* Enable Protected Mode    (RW) */
#define X86_CR0_MP              0x00000002      /* Monitor Coprocessor      (RW) */
#define X86_CR0_EM              0x00000004      /* Require FPU Emulation    (RO) */
#define X86_CR0_TS              0x00000008      /* Task Switched            (RW) */
#define X86_CR0_ET              0x00000010      /* Extension type           (RO) */
#define X86_CR0_NE              0x00000020      /* Numeric Error Reporting  (RW) */
#define X86_CR0_WP              0x00010000      /* Supervisor Write Protect (RW) */
#define X86_CR0_AM              0x00040000      /* Alignment Checking       (RW) */
#define X86_CR0_NW              0x20000000      /* Not Write-Through        (RW) */
#define X86_CR0_CD              0x40000000      /* Cache Disable            (RW) */
#define X86_CR0_PG              0x80000000      /* Paging                   (RW) */

/*
 * Intel CPU features in CR4
 */
#define X86_CR4_VME		0x0001  /* enable vm86 extensions */
#define X86_CR4_PVI		0x0002  /* virtual interrupts flag enable */
#define X86_CR4_TSD		0x0004  /* disable time stamp at ipl 3 */
#define X86_CR4_DE		0x0008  /* enable debugging extensions */
#define X86_CR4_PSE		0x0010  /* enable page size extensions */
#define X86_CR4_PAE		0x0020  /* enable physical address extensions */
#define X86_CR4_MCE		0x0040  /* Machine check enable */
#define X86_CR4_PGE		0x0080  /* enable global pages */
#define X86_CR4_PCE		0x0100  /* enable performance counters at ipl 3 */
#define X86_CR4_OSFXSR		0x0200  /* enable fast FPU save and restore */
#define X86_CR4_OSXMMEXCPT	0x0400  /* enable unmasked SSE exceptions */
#define X86_CR4_VMXE		0x2000  /* enable VMX */

/* MSRs & bits used for VMX enabling */
#define MSR_IA32_VMX_BASIC   		0x480
#define MSR_IA32_VMX_PINBASED_CTLS	0x481
#define MSR_IA32_VMX_PROCBASED_CTLS	0x482
#define MSR_IA32_VMX_EXIT_CTLS		0x483
#define MSR_IA32_VMX_ENTRY_CTLS		0x484

#define MSR_IA32_SYSENTER_CS		0x174
#define MSR_IA32_SYSENTER_ESP		0x175
#define MSR_IA32_SYSENTER_EIP		0x176
#define MSR_IA32_DEBUGCTL			0x1d9
#define IA32_FEATURE_CONTROL        0x3A //58

#define MSR_FS_BASE         0xc0000100        /* 64bit FS base */
#define MSR_GS_BASE         0xc0000101        /* 64bit GS base */

typedef struct _GUEST_REGS{
  ULONG64 rax;                  // 0x00         // NOT VALID FOR SVM
  ULONG64 rcx;
  ULONG64 rdx;                  // 0x10
  ULONG64 rbx;
  ULONG64 rsp;                  // 0x20         // rsp is not stored here on SVM
  ULONG64 rbp;
  ULONG64 rsi;                  // 0x30
  ULONG64 rdi;
  ULONG64 r8;                   // 0x40
  ULONG64 r9;
  ULONG64 r10;                  // 0x50
  ULONG64 r11;
  ULONG64 r12;                  // 0x60
  ULONG64 r13;
  ULONG64 r14;                  // 0x70
  ULONG64 r15;
} GUEST_REGS, *PGUEST_REGS;

#define VM_EXIT_IA32E_MODE              0x00000200
#define VM_EXIT_ACK_INTR_ON_EXIT        0x00008000

#define VM_ENTRY_IA32E_MODE             0x00000200

// ntamd64_x.h
#define KGDT64_NULL (0 * 16)    // NULL descriptor
#define KGDT64_R0_CODE (1 * 16) // kernel mode 64-bit code
#define KGDT64_R0_DATA (1 * 16) + 8     // kernel mode 64-bit data (stack)
#define KGDT64_R3_CMCODE (2 * 16)       // user mode 32-bit code
#define KGDT64_R3_DATA (2 * 16) + 8     // user mode 32-bit data
#define KGDT64_R3_CODE (3 * 16) // user mode 64-bit code
#define KGDT64_SYS_TSS (4 * 16) // kernel mode system task state
#define KGDT64_R3_CMTEB (5 * 16)        // user mode 32-bit TEB
#define KGDT64_R0_CMCODE (6 * 16)       // kernel mode 32-bit code

// this must be synchronized with CmSetBluepillSelectors() (common-asm.asm)
#define	BP_GDT64_CODE		KGDT64_R0_CODE  // cs
#define BP_GDT64_DATA		KGDT64_R0_DATA  // ds, es, ss
#define BP_GDT64_SYS_TSS	KGDT64_SYS_TSS  // tr
#define BP_GDT64_PCR		KGDT64_R0_DATA  // gs

enum
{
  GUEST_ES_SELECTOR = 0x00000800,
  GUEST_CS_SELECTOR = 0x00000802,
  GUEST_SS_SELECTOR = 0x00000804,
  GUEST_DS_SELECTOR = 0x00000806,
  GUEST_FS_SELECTOR = 0x00000808,
  GUEST_GS_SELECTOR = 0x0000080a,
  GUEST_LDTR_SELECTOR = 0x0000080c,
  GUEST_TR_SELECTOR = 0x0000080e,
  HOST_ES_SELECTOR = 0x00000c00,
  HOST_CS_SELECTOR = 0x00000c02,
  HOST_SS_SELECTOR = 0x00000c04,
  HOST_DS_SELECTOR = 0x00000c06,
  HOST_FS_SELECTOR = 0x00000c08,
  HOST_GS_SELECTOR = 0x00000c0a,
  HOST_TR_SELECTOR = 0x00000c0c,
  IO_BITMAP_A = 0x00002000,
  IO_BITMAP_A_HIGH = 0x00002001,
  IO_BITMAP_B = 0x00002002,
  IO_BITMAP_B_HIGH = 0x00002003,
  MSR_BITMAP = 0x00002004,
  MSR_BITMAP_HIGH = 0x00002005,
  VM_EXIT_MSR_STORE_ADDR = 0x00002006,
  VM_EXIT_MSR_STORE_ADDR_HIGH = 0x00002007,
  VM_EXIT_MSR_LOAD_ADDR = 0x00002008,
  VM_EXIT_MSR_LOAD_ADDR_HIGH = 0x00002009,
  VM_ENTRY_MSR_LOAD_ADDR = 0x0000200a,
  VM_ENTRY_MSR_LOAD_ADDR_HIGH = 0x0000200b,
  TSC_OFFSET = 0x00002010,
  TSC_OFFSET_HIGH = 0x00002011,
  VIRTUAL_APIC_PAGE_ADDR = 0x00002012,
  VIRTUAL_APIC_PAGE_ADDR_HIGH = 0x00002013,
  VMCS_LINK_POINTER = 0x00002800,
  VMCS_LINK_POINTER_HIGH = 0x00002801,
  GUEST_IA32_DEBUGCTL = 0x00002802,
  GUEST_IA32_DEBUGCTL_HIGH = 0x00002803,
  PIN_BASED_VM_EXEC_CONTROL = 0x00004000,
  CPU_BASED_VM_EXEC_CONTROL = 0x00004002,
  EXCEPTION_BITMAP = 0x00004004,
  PAGE_FAULT_ERROR_CODE_MASK = 0x00004006,
  PAGE_FAULT_ERROR_CODE_MATCH = 0x00004008,
  CR3_TARGET_COUNT = 0x0000400a,
  VM_EXIT_CONTROLS = 0x0000400c,
  VM_EXIT_MSR_STORE_COUNT = 0x0000400e,
  VM_EXIT_MSR_LOAD_COUNT = 0x00004010,
  VM_ENTRY_CONTROLS = 0x00004012,
  VM_ENTRY_MSR_LOAD_COUNT = 0x00004014,
  VM_ENTRY_INTR_INFO_FIELD = 0x00004016,
  VM_ENTRY_EXCEPTION_ERROR_CODE = 0x00004018,
  VM_ENTRY_INSTRUCTION_LEN = 0x0000401a,
  TPR_THRESHOLD = 0x0000401c,
  SECONDARY_VM_EXEC_CONTROL = 0x0000401e,
  VM_INSTRUCTION_ERROR = 0x00004400,
  VM_EXIT_REASON = 0x00004402,
  VM_EXIT_INTR_INFO = 0x00004404,
  VM_EXIT_INTR_ERROR_CODE = 0x00004406,
  IDT_VECTORING_INFO_FIELD = 0x00004408,
  IDT_VECTORING_ERROR_CODE = 0x0000440a,
  VM_EXIT_INSTRUCTION_LEN = 0x0000440c,
  VMX_INSTRUCTION_INFO = 0x0000440e,
  GUEST_ES_LIMIT = 0x00004800,
  GUEST_CS_LIMIT = 0x00004802,
  GUEST_SS_LIMIT = 0x00004804,
  GUEST_DS_LIMIT = 0x00004806,
  GUEST_FS_LIMIT = 0x00004808,
  GUEST_GS_LIMIT = 0x0000480a,
  GUEST_LDTR_LIMIT = 0x0000480c,
  GUEST_TR_LIMIT = 0x0000480e,
  GUEST_GDTR_LIMIT = 0x00004810,
  GUEST_IDTR_LIMIT = 0x00004812,
  GUEST_ES_AR_BYTES = 0x00004814,
  GUEST_CS_AR_BYTES = 0x00004816,
  GUEST_SS_AR_BYTES = 0x00004818,
  GUEST_DS_AR_BYTES = 0x0000481a,
  GUEST_FS_AR_BYTES = 0x0000481c,
  GUEST_GS_AR_BYTES = 0x0000481e,
  GUEST_LDTR_AR_BYTES = 0x00004820,
  GUEST_TR_AR_BYTES = 0x00004822,
  GUEST_INTERRUPTIBILITY_STATE = 0x00004824,
  GUEST_ACTIVITY_STATE = 0x00004826,
  GUEST_SM_BASE = 0x00004828,
  GUEST_SYSENTER_CS = 0x0000482A,
  HOST_IA32_SYSENTER_CS = 0x00004c00,
  CR0_GUEST_HOST_MASK = 0x00006000,
  CR4_GUEST_HOST_MASK = 0x00006002,
  CR0_READ_SHADOW = 0x00006004,
  CR4_READ_SHADOW = 0x00006006,
  CR3_TARGET_VALUE0 = 0x00006008,
  CR3_TARGET_VALUE1 = 0x0000600a,
  CR3_TARGET_VALUE2 = 0x0000600c,
  CR3_TARGET_VALUE3 = 0x0000600e,
  EXIT_QUALIFICATION = 0x00006400,
  GUEST_LINEAR_ADDRESS = 0x0000640a,
  GUEST_CR0 = 0x00006800,
  GUEST_CR3 = 0x00006802,
  GUEST_CR4 = 0x00006804,
  GUEST_ES_BASE = 0x00006806,
  GUEST_CS_BASE = 0x00006808,
  GUEST_SS_BASE = 0x0000680a,
  GUEST_DS_BASE = 0x0000680c,
  GUEST_FS_BASE = 0x0000680e,
  GUEST_GS_BASE = 0x00006810,
  GUEST_LDTR_BASE = 0x00006812,
  GUEST_TR_BASE = 0x00006814,
  GUEST_GDTR_BASE = 0x00006816,
  GUEST_IDTR_BASE = 0x00006818,
  GUEST_DR7 = 0x0000681a,
  GUEST_RSP = 0x0000681c,
  GUEST_RIP = 0x0000681e,
  GUEST_RFLAGS = 0x00006820,
  GUEST_PENDING_DBG_EXCEPTIONS = 0x00006822,
  GUEST_SYSENTER_ESP = 0x00006824,
  GUEST_SYSENTER_EIP = 0x00006826,
  HOST_CR0 = 0x00006c00,
  HOST_CR3 = 0x00006c02,
  HOST_CR4 = 0x00006c04,
  HOST_FS_BASE = 0x00006c06,
  HOST_GS_BASE = 0x00006c08,
  HOST_TR_BASE = 0x00006c0a,
  HOST_GDTR_BASE = 0x00006c0c,
  HOST_IDTR_BASE = 0x00006c0e,
  HOST_IA32_SYSENTER_ESP = 0x00006c10,
  HOST_IA32_SYSENTER_EIP = 0x00006c12,
  HOST_RSP = 0x00006c14,
  HOST_RIP = 0x00006c16,

  CPU_BASED_RDTSC_EXITING = 0x00001000,
};


/// See: Definitions of Secondary Processor-Based VM-Execution Controls
typedef union _VmxSecondaryProcessorBasedControls
{
    unsigned int all;
    struct
    {
        unsigned virtualize_apic_accesses : 1;      //!< [0]
        unsigned enable_ept : 1;                    //!< [1]
        unsigned descriptor_table_exiting : 1;      //!< [2]
        unsigned enable_rdtscp : 1;                 //!< [3]
        unsigned virtualize_x2apic_mode : 1;        //!< [4]
        unsigned enable_vpid : 1;                   //!< [5]
        unsigned wbinvd_exiting : 1;                //!< [6]
        unsigned unrestricted_guest : 1;            //!< [7]
        unsigned apic_register_virtualization : 1;  //!< [8]
        unsigned virtual_interrupt_delivery : 1;    //!< [9]
        unsigned pause_loop_exiting : 1;            //!< [10]
        unsigned rdrand_exiting : 1;                //!< [11]
        unsigned enable_invpcid : 1;                //!< [12]
        unsigned enable_vm_functions : 1;           //!< [13]
        unsigned vmcs_shadowing : 1;                //!< [14]
        unsigned reserved1 : 1;                     //!< [15]
        unsigned rdseed_exiting : 1;                //!< [16]
        unsigned reserved2 : 1;                     //!< [17]
        unsigned ept_violation_ve : 1;              //!< [18]
        unsigned reserved3 : 1;                     //!< [19]
        unsigned enable_xsaves_xstors : 1;          //!< [20]
        unsigned reserved4 : 4;                     //!< [21:24]
        unsigned use_tsc_scaling : 1;               //!< [25]
    } fields;
}VmxSecondaryProcessorBasedControls;


typedef union _VMX_CPU_BASED_CONTROLS
{
    ULONG32 All;
    struct
    {
        ULONG32 Reserved1 : 2;                 // [0-1]
        ULONG32 InterruptWindowExiting : 1;    // [2]
        ULONG32 UseTSCOffseting : 1;           // [3]
        ULONG32 Reserved2 : 3;                 // [4-6]
        ULONG32 HLTExiting : 1;                // [7]
        ULONG32 Reserved3 : 1;                 // [8]
        ULONG32 INVLPGExiting : 1;             // [9]
        ULONG32 MWAITExiting : 1;              // [10]
        ULONG32 RDPMCExiting : 1;              // [11]
        ULONG32 RDTSCExiting : 1;              // [12]
        ULONG32 Reserved4 : 2;                 // [13-14]
        ULONG32 CR3LoadExiting : 1;            // [15]
        ULONG32 CR3StoreExiting : 1;           // [16]
        ULONG32 Reserved5 : 2;                 // [17-18]
        ULONG32 CR8LoadExiting : 1;            // [19]
        ULONG32 CR8StoreExiting : 1;           // [20]
        ULONG32 UseTPRShadowExiting : 1;       // [21]
        ULONG32 NMIWindowExiting : 1;          // [22]
        ULONG32 MovDRExiting : 1;              // [23]
        ULONG32 UnconditionalIOExiting : 1;    // [24]
        ULONG32 UseIOBitmaps : 1;              // [25]
        ULONG32 Reserved6 : 1;                 // [26]
        ULONG32 MonitorTrapFlag : 1;           // [27]
        ULONG32 UseMSRBitmaps : 1;             // [28]
        ULONG32 MONITORExiting : 1;            // [29]
        ULONG32 PAUSEExiting : 1;              // [30]
        ULONG32 ActivateSecondaryControl : 1;  // [31]
    } Fields;
} VMX_CPU_BASED_CONTROLS, *PVMX_CPU_BASED_CONTROLS;


#define TAG	'tset' //test
#define NBP_MAGIC ((ULONG32)'!LTI')
#define NBP_HYPERCALL_UNLOAD    0x1

#define REG_MASK			0x07
#define REG_GP				0x08
#define REG_GP_ADDITIONAL	0x10
#define REG_CONTROL			0x20
#define REG_DEBUG			0x40
#define REG_RFLAGS			0x80

#define	REG_RAX	REG_GP | 0
#define REG_RCX	REG_GP | 1
#define REG_RDX	REG_GP | 2
#define REG_RBX	REG_GP | 3
#define REG_RSP	REG_GP | 4
#define REG_RBP	REG_GP | 5
#define REG_RSI	REG_GP | 6
#define REG_RDI	REG_GP | 7

#define	REG_R8	REG_GP_ADDITIONAL | 0
#define	REG_R9	REG_GP_ADDITIONAL | 1
#define	REG_R10	REG_GP_ADDITIONAL | 2
#define	REG_R11	REG_GP_ADDITIONAL | 3
#define	REG_R12	REG_GP_ADDITIONAL | 4
#define	REG_R13	REG_GP_ADDITIONAL | 5
#define	REG_R14	REG_GP_ADDITIONAL | 6
#define	REG_R15	REG_GP_ADDITIONAL | 7

#define REG_CR0	REG_CONTROL | 0
#define REG_CR2	REG_CONTROL | 2
#define REG_CR3	REG_CONTROL | 3
#define REG_CR4	REG_CONTROL | 4
#define REG_CR8	REG_CONTROL | 8


//////////////////////////////////////////////////////////////////////////////////////////////////
//一些汇编实现的函数。

USHORT RegGetCs ();
USHORT RegGetDs ();
USHORT RegGetEs ();
USHORT RegGetSs ();
USHORT RegGetFs ();
USHORT RegGetGs ();
USHORT GetGdtLimit ();
USHORT GetTrSelector ();
USHORT GetLdtr ();

VOID VmxVmCall (ULONG32 HypercallNumber);
ULONG64 VmxRead (ULONG64 field);
VOID  VmxVmexitHandler();
NTSTATUS  CmSubvert ();
NTSTATUS  CmGuestEip (PVOID);
VOID GetCpuIdInfo (ULONG32 fn, OUT PULONG32 ret_eax, OUT PULONG32 ret_ebx, OUT PULONG32 ret_ecx, OUT PULONG32 ret_edx);
size_t get_access_rights(size_t x);