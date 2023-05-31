/* This file is generated by venus-protocol.  See vn_protocol_driver.h. */

/*
 * Copyright 2020 Google LLC
 * SPDX-License-Identifier: MIT
 */

#ifndef VN_PROTOCOL_DRIVER_DESCRIPTOR_SET_LAYOUT_H
#define VN_PROTOCOL_DRIVER_DESCRIPTOR_SET_LAYOUT_H

#include "vn_instance.h"
#include "vn_protocol_driver_structs.h"

/* struct VkDescriptorSetLayoutBinding */

static inline size_t
vn_sizeof_VkDescriptorSetLayoutBinding(const VkDescriptorSetLayoutBinding *val)
{
    size_t size = 0;
    size += vn_sizeof_uint32_t(&val->binding);
    size += vn_sizeof_VkDescriptorType(&val->descriptorType);
    size += vn_sizeof_uint32_t(&val->descriptorCount);
    size += vn_sizeof_VkFlags(&val->stageFlags);
    if (val->pImmutableSamplers) {
        size += vn_sizeof_array_size(val->descriptorCount);
        for (uint32_t i = 0; i < val->descriptorCount; i++)
            size += vn_sizeof_VkSampler(&val->pImmutableSamplers[i]);
    } else {
        size += vn_sizeof_array_size(0);
    }
    return size;
}

static inline void
vn_encode_VkDescriptorSetLayoutBinding(struct vn_cs_encoder *enc, const VkDescriptorSetLayoutBinding *val)
{
    vn_encode_uint32_t(enc, &val->binding);
    vn_encode_VkDescriptorType(enc, &val->descriptorType);
    vn_encode_uint32_t(enc, &val->descriptorCount);
    vn_encode_VkFlags(enc, &val->stageFlags);
    if (val->pImmutableSamplers) {
        vn_encode_array_size(enc, val->descriptorCount);
        for (uint32_t i = 0; i < val->descriptorCount; i++)
            vn_encode_VkSampler(enc, &val->pImmutableSamplers[i]);
    } else {
        vn_encode_array_size(enc, 0);
    }
}

/* struct VkDescriptorSetLayoutBindingFlagsCreateInfo chain */

static inline size_t
vn_sizeof_VkDescriptorSetLayoutBindingFlagsCreateInfo_pnext(const void *val)
{
    /* no known/supported struct */
    return vn_sizeof_simple_pointer(NULL);
}

static inline size_t
vn_sizeof_VkDescriptorSetLayoutBindingFlagsCreateInfo_self(const VkDescriptorSetLayoutBindingFlagsCreateInfo *val)
{
    size_t size = 0;
    /* skip val->{sType,pNext} */
    size += vn_sizeof_uint32_t(&val->bindingCount);
    if (val->pBindingFlags) {
        size += vn_sizeof_array_size(val->bindingCount);
        for (uint32_t i = 0; i < val->bindingCount; i++)
            size += vn_sizeof_VkFlags(&val->pBindingFlags[i]);
    } else {
        size += vn_sizeof_array_size(0);
    }
    return size;
}

static inline size_t
vn_sizeof_VkDescriptorSetLayoutBindingFlagsCreateInfo(const VkDescriptorSetLayoutBindingFlagsCreateInfo *val)
{
    size_t size = 0;

    size += vn_sizeof_VkStructureType(&val->sType);
    size += vn_sizeof_VkDescriptorSetLayoutBindingFlagsCreateInfo_pnext(val->pNext);
    size += vn_sizeof_VkDescriptorSetLayoutBindingFlagsCreateInfo_self(val);

    return size;
}

static inline void
vn_encode_VkDescriptorSetLayoutBindingFlagsCreateInfo_pnext(struct vn_cs_encoder *enc, const void *val)
{
    /* no known/supported struct */
    vn_encode_simple_pointer(enc, NULL);
}

static inline void
vn_encode_VkDescriptorSetLayoutBindingFlagsCreateInfo_self(struct vn_cs_encoder *enc, const VkDescriptorSetLayoutBindingFlagsCreateInfo *val)
{
    /* skip val->{sType,pNext} */
    vn_encode_uint32_t(enc, &val->bindingCount);
    if (val->pBindingFlags) {
        vn_encode_array_size(enc, val->bindingCount);
        for (uint32_t i = 0; i < val->bindingCount; i++)
            vn_encode_VkFlags(enc, &val->pBindingFlags[i]);
    } else {
        vn_encode_array_size(enc, 0);
    }
}

static inline void
vn_encode_VkDescriptorSetLayoutBindingFlagsCreateInfo(struct vn_cs_encoder *enc, const VkDescriptorSetLayoutBindingFlagsCreateInfo *val)
{
    assert(val->sType == VK_STRUCTURE_TYPE_DESCRIPTOR_SET_LAYOUT_BINDING_FLAGS_CREATE_INFO);
    vn_encode_VkStructureType(enc, &(VkStructureType){ VK_STRUCTURE_TYPE_DESCRIPTOR_SET_LAYOUT_BINDING_FLAGS_CREATE_INFO });
    vn_encode_VkDescriptorSetLayoutBindingFlagsCreateInfo_pnext(enc, val->pNext);
    vn_encode_VkDescriptorSetLayoutBindingFlagsCreateInfo_self(enc, val);
}

/* struct VkDescriptorSetLayoutCreateInfo chain */

static inline size_t
vn_sizeof_VkDescriptorSetLayoutCreateInfo_pnext(const void *val)
{
    const VkBaseInStructure *pnext = val;
    size_t size = 0;

    while (pnext) {
        switch ((int32_t)pnext->sType) {
        case VK_STRUCTURE_TYPE_DESCRIPTOR_SET_LAYOUT_BINDING_FLAGS_CREATE_INFO:
            size += vn_sizeof_simple_pointer(pnext);
            size += vn_sizeof_VkStructureType(&pnext->sType);
            size += vn_sizeof_VkDescriptorSetLayoutCreateInfo_pnext(pnext->pNext);
            size += vn_sizeof_VkDescriptorSetLayoutBindingFlagsCreateInfo_self((const VkDescriptorSetLayoutBindingFlagsCreateInfo *)pnext);
            return size;
        default:
            /* ignore unknown/unsupported struct */
            break;
        }
        pnext = pnext->pNext;
    }

    return vn_sizeof_simple_pointer(NULL);
}

static inline size_t
vn_sizeof_VkDescriptorSetLayoutCreateInfo_self(const VkDescriptorSetLayoutCreateInfo *val)
{
    size_t size = 0;
    /* skip val->{sType,pNext} */
    size += vn_sizeof_VkFlags(&val->flags);
    size += vn_sizeof_uint32_t(&val->bindingCount);
    if (val->pBindings) {
        size += vn_sizeof_array_size(val->bindingCount);
        for (uint32_t i = 0; i < val->bindingCount; i++)
            size += vn_sizeof_VkDescriptorSetLayoutBinding(&val->pBindings[i]);
    } else {
        size += vn_sizeof_array_size(0);
    }
    return size;
}

static inline size_t
vn_sizeof_VkDescriptorSetLayoutCreateInfo(const VkDescriptorSetLayoutCreateInfo *val)
{
    size_t size = 0;

    size += vn_sizeof_VkStructureType(&val->sType);
    size += vn_sizeof_VkDescriptorSetLayoutCreateInfo_pnext(val->pNext);
    size += vn_sizeof_VkDescriptorSetLayoutCreateInfo_self(val);

    return size;
}

static inline void
vn_encode_VkDescriptorSetLayoutCreateInfo_pnext(struct vn_cs_encoder *enc, const void *val)
{
    const VkBaseInStructure *pnext = val;

    while (pnext) {
        switch ((int32_t)pnext->sType) {
        case VK_STRUCTURE_TYPE_DESCRIPTOR_SET_LAYOUT_BINDING_FLAGS_CREATE_INFO:
            vn_encode_simple_pointer(enc, pnext);
            vn_encode_VkStructureType(enc, &pnext->sType);
            vn_encode_VkDescriptorSetLayoutCreateInfo_pnext(enc, pnext->pNext);
            vn_encode_VkDescriptorSetLayoutBindingFlagsCreateInfo_self(enc, (const VkDescriptorSetLayoutBindingFlagsCreateInfo *)pnext);
            return;
        default:
            /* ignore unknown/unsupported struct */
            break;
        }
        pnext = pnext->pNext;
    }

    vn_encode_simple_pointer(enc, NULL);
}

static inline void
vn_encode_VkDescriptorSetLayoutCreateInfo_self(struct vn_cs_encoder *enc, const VkDescriptorSetLayoutCreateInfo *val)
{
    /* skip val->{sType,pNext} */
    vn_encode_VkFlags(enc, &val->flags);
    vn_encode_uint32_t(enc, &val->bindingCount);
    if (val->pBindings) {
        vn_encode_array_size(enc, val->bindingCount);
        for (uint32_t i = 0; i < val->bindingCount; i++)
            vn_encode_VkDescriptorSetLayoutBinding(enc, &val->pBindings[i]);
    } else {
        vn_encode_array_size(enc, 0);
    }
}

static inline void
vn_encode_VkDescriptorSetLayoutCreateInfo(struct vn_cs_encoder *enc, const VkDescriptorSetLayoutCreateInfo *val)
{
    assert(val->sType == VK_STRUCTURE_TYPE_DESCRIPTOR_SET_LAYOUT_CREATE_INFO);
    vn_encode_VkStructureType(enc, &(VkStructureType){ VK_STRUCTURE_TYPE_DESCRIPTOR_SET_LAYOUT_CREATE_INFO });
    vn_encode_VkDescriptorSetLayoutCreateInfo_pnext(enc, val->pNext);
    vn_encode_VkDescriptorSetLayoutCreateInfo_self(enc, val);
}

/* struct VkDescriptorSetVariableDescriptorCountLayoutSupport chain */

static inline size_t
vn_sizeof_VkDescriptorSetVariableDescriptorCountLayoutSupport_pnext(const void *val)
{
    /* no known/supported struct */
    return vn_sizeof_simple_pointer(NULL);
}

static inline size_t
vn_sizeof_VkDescriptorSetVariableDescriptorCountLayoutSupport_self(const VkDescriptorSetVariableDescriptorCountLayoutSupport *val)
{
    size_t size = 0;
    /* skip val->{sType,pNext} */
    size += vn_sizeof_uint32_t(&val->maxVariableDescriptorCount);
    return size;
}

static inline size_t
vn_sizeof_VkDescriptorSetVariableDescriptorCountLayoutSupport(const VkDescriptorSetVariableDescriptorCountLayoutSupport *val)
{
    size_t size = 0;

    size += vn_sizeof_VkStructureType(&val->sType);
    size += vn_sizeof_VkDescriptorSetVariableDescriptorCountLayoutSupport_pnext(val->pNext);
    size += vn_sizeof_VkDescriptorSetVariableDescriptorCountLayoutSupport_self(val);

    return size;
}

static inline void
vn_decode_VkDescriptorSetVariableDescriptorCountLayoutSupport_pnext(struct vn_cs_decoder *dec, const void *val)
{
    /* no known/supported struct */
    if (vn_decode_simple_pointer(dec))
        assert(false);
}

static inline void
vn_decode_VkDescriptorSetVariableDescriptorCountLayoutSupport_self(struct vn_cs_decoder *dec, VkDescriptorSetVariableDescriptorCountLayoutSupport *val)
{
    /* skip val->{sType,pNext} */
    vn_decode_uint32_t(dec, &val->maxVariableDescriptorCount);
}

static inline void
vn_decode_VkDescriptorSetVariableDescriptorCountLayoutSupport(struct vn_cs_decoder *dec, VkDescriptorSetVariableDescriptorCountLayoutSupport *val)
{
    VkStructureType stype;
    vn_decode_VkStructureType(dec, &stype);
    assert(stype == VK_STRUCTURE_TYPE_DESCRIPTOR_SET_VARIABLE_DESCRIPTOR_COUNT_LAYOUT_SUPPORT);

    assert(val->sType == stype);
    vn_decode_VkDescriptorSetVariableDescriptorCountLayoutSupport_pnext(dec, val->pNext);
    vn_decode_VkDescriptorSetVariableDescriptorCountLayoutSupport_self(dec, val);
}

static inline size_t
vn_sizeof_VkDescriptorSetVariableDescriptorCountLayoutSupport_pnext_partial(const void *val)
{
    /* no known/supported struct */
    return vn_sizeof_simple_pointer(NULL);
}

static inline size_t
vn_sizeof_VkDescriptorSetVariableDescriptorCountLayoutSupport_self_partial(const VkDescriptorSetVariableDescriptorCountLayoutSupport *val)
{
    size_t size = 0;
    /* skip val->{sType,pNext} */
    /* skip val->maxVariableDescriptorCount */
    return size;
}

static inline size_t
vn_sizeof_VkDescriptorSetVariableDescriptorCountLayoutSupport_partial(const VkDescriptorSetVariableDescriptorCountLayoutSupport *val)
{
    size_t size = 0;

    size += vn_sizeof_VkStructureType(&val->sType);
    size += vn_sizeof_VkDescriptorSetVariableDescriptorCountLayoutSupport_pnext_partial(val->pNext);
    size += vn_sizeof_VkDescriptorSetVariableDescriptorCountLayoutSupport_self_partial(val);

    return size;
}

static inline void
vn_encode_VkDescriptorSetVariableDescriptorCountLayoutSupport_pnext_partial(struct vn_cs_encoder *enc, const void *val)
{
    /* no known/supported struct */
    vn_encode_simple_pointer(enc, NULL);
}

static inline void
vn_encode_VkDescriptorSetVariableDescriptorCountLayoutSupport_self_partial(struct vn_cs_encoder *enc, const VkDescriptorSetVariableDescriptorCountLayoutSupport *val)
{
    /* skip val->{sType,pNext} */
    /* skip val->maxVariableDescriptorCount */
}

static inline void
vn_encode_VkDescriptorSetVariableDescriptorCountLayoutSupport_partial(struct vn_cs_encoder *enc, const VkDescriptorSetVariableDescriptorCountLayoutSupport *val)
{
    assert(val->sType == VK_STRUCTURE_TYPE_DESCRIPTOR_SET_VARIABLE_DESCRIPTOR_COUNT_LAYOUT_SUPPORT);
    vn_encode_VkStructureType(enc, &(VkStructureType){ VK_STRUCTURE_TYPE_DESCRIPTOR_SET_VARIABLE_DESCRIPTOR_COUNT_LAYOUT_SUPPORT });
    vn_encode_VkDescriptorSetVariableDescriptorCountLayoutSupport_pnext_partial(enc, val->pNext);
    vn_encode_VkDescriptorSetVariableDescriptorCountLayoutSupport_self_partial(enc, val);
}

/* struct VkDescriptorSetLayoutSupport chain */

static inline size_t
vn_sizeof_VkDescriptorSetLayoutSupport_pnext(const void *val)
{
    const VkBaseInStructure *pnext = val;
    size_t size = 0;

    while (pnext) {
        switch ((int32_t)pnext->sType) {
        case VK_STRUCTURE_TYPE_DESCRIPTOR_SET_VARIABLE_DESCRIPTOR_COUNT_LAYOUT_SUPPORT:
            size += vn_sizeof_simple_pointer(pnext);
            size += vn_sizeof_VkStructureType(&pnext->sType);
            size += vn_sizeof_VkDescriptorSetLayoutSupport_pnext(pnext->pNext);
            size += vn_sizeof_VkDescriptorSetVariableDescriptorCountLayoutSupport_self((const VkDescriptorSetVariableDescriptorCountLayoutSupport *)pnext);
            return size;
        default:
            /* ignore unknown/unsupported struct */
            break;
        }
        pnext = pnext->pNext;
    }

    return vn_sizeof_simple_pointer(NULL);
}

static inline size_t
vn_sizeof_VkDescriptorSetLayoutSupport_self(const VkDescriptorSetLayoutSupport *val)
{
    size_t size = 0;
    /* skip val->{sType,pNext} */
    size += vn_sizeof_VkBool32(&val->supported);
    return size;
}

static inline size_t
vn_sizeof_VkDescriptorSetLayoutSupport(const VkDescriptorSetLayoutSupport *val)
{
    size_t size = 0;

    size += vn_sizeof_VkStructureType(&val->sType);
    size += vn_sizeof_VkDescriptorSetLayoutSupport_pnext(val->pNext);
    size += vn_sizeof_VkDescriptorSetLayoutSupport_self(val);

    return size;
}

static inline void
vn_decode_VkDescriptorSetLayoutSupport_pnext(struct vn_cs_decoder *dec, const void *val)
{
    VkBaseOutStructure *pnext = (VkBaseOutStructure *)val;
    VkStructureType stype;

    if (!vn_decode_simple_pointer(dec))
        return;

    vn_decode_VkStructureType(dec, &stype);
    while (true) {
        assert(pnext);
        if (pnext->sType == stype)
            break;
    }

    switch ((int32_t)pnext->sType) {
    case VK_STRUCTURE_TYPE_DESCRIPTOR_SET_VARIABLE_DESCRIPTOR_COUNT_LAYOUT_SUPPORT:
        vn_decode_VkDescriptorSetLayoutSupport_pnext(dec, pnext->pNext);
        vn_decode_VkDescriptorSetVariableDescriptorCountLayoutSupport_self(dec, (VkDescriptorSetVariableDescriptorCountLayoutSupport *)pnext);
        break;
    default:
        assert(false);
        break;
    }
}

static inline void
vn_decode_VkDescriptorSetLayoutSupport_self(struct vn_cs_decoder *dec, VkDescriptorSetLayoutSupport *val)
{
    /* skip val->{sType,pNext} */
    vn_decode_VkBool32(dec, &val->supported);
}

static inline void
vn_decode_VkDescriptorSetLayoutSupport(struct vn_cs_decoder *dec, VkDescriptorSetLayoutSupport *val)
{
    VkStructureType stype;
    vn_decode_VkStructureType(dec, &stype);
    assert(stype == VK_STRUCTURE_TYPE_DESCRIPTOR_SET_LAYOUT_SUPPORT);

    assert(val->sType == stype);
    vn_decode_VkDescriptorSetLayoutSupport_pnext(dec, val->pNext);
    vn_decode_VkDescriptorSetLayoutSupport_self(dec, val);
}

static inline size_t
vn_sizeof_VkDescriptorSetLayoutSupport_pnext_partial(const void *val)
{
    const VkBaseInStructure *pnext = val;
    size_t size = 0;

    while (pnext) {
        switch ((int32_t)pnext->sType) {
        case VK_STRUCTURE_TYPE_DESCRIPTOR_SET_VARIABLE_DESCRIPTOR_COUNT_LAYOUT_SUPPORT:
            size += vn_sizeof_simple_pointer(pnext);
            size += vn_sizeof_VkStructureType(&pnext->sType);
            size += vn_sizeof_VkDescriptorSetLayoutSupport_pnext_partial(pnext->pNext);
            size += vn_sizeof_VkDescriptorSetVariableDescriptorCountLayoutSupport_self_partial((const VkDescriptorSetVariableDescriptorCountLayoutSupport *)pnext);
            return size;
        default:
            /* ignore unknown/unsupported struct */
            break;
        }
        pnext = pnext->pNext;
    }

    return vn_sizeof_simple_pointer(NULL);
}

static inline size_t
vn_sizeof_VkDescriptorSetLayoutSupport_self_partial(const VkDescriptorSetLayoutSupport *val)
{
    size_t size = 0;
    /* skip val->{sType,pNext} */
    /* skip val->supported */
    return size;
}

static inline size_t
vn_sizeof_VkDescriptorSetLayoutSupport_partial(const VkDescriptorSetLayoutSupport *val)
{
    size_t size = 0;

    size += vn_sizeof_VkStructureType(&val->sType);
    size += vn_sizeof_VkDescriptorSetLayoutSupport_pnext_partial(val->pNext);
    size += vn_sizeof_VkDescriptorSetLayoutSupport_self_partial(val);

    return size;
}

static inline void
vn_encode_VkDescriptorSetLayoutSupport_pnext_partial(struct vn_cs_encoder *enc, const void *val)
{
    const VkBaseInStructure *pnext = val;

    while (pnext) {
        switch ((int32_t)pnext->sType) {
        case VK_STRUCTURE_TYPE_DESCRIPTOR_SET_VARIABLE_DESCRIPTOR_COUNT_LAYOUT_SUPPORT:
            vn_encode_simple_pointer(enc, pnext);
            vn_encode_VkStructureType(enc, &pnext->sType);
            vn_encode_VkDescriptorSetLayoutSupport_pnext_partial(enc, pnext->pNext);
            vn_encode_VkDescriptorSetVariableDescriptorCountLayoutSupport_self_partial(enc, (const VkDescriptorSetVariableDescriptorCountLayoutSupport *)pnext);
            return;
        default:
            /* ignore unknown/unsupported struct */
            break;
        }
        pnext = pnext->pNext;
    }

    vn_encode_simple_pointer(enc, NULL);
}

static inline void
vn_encode_VkDescriptorSetLayoutSupport_self_partial(struct vn_cs_encoder *enc, const VkDescriptorSetLayoutSupport *val)
{
    /* skip val->{sType,pNext} */
    /* skip val->supported */
}

static inline void
vn_encode_VkDescriptorSetLayoutSupport_partial(struct vn_cs_encoder *enc, const VkDescriptorSetLayoutSupport *val)
{
    assert(val->sType == VK_STRUCTURE_TYPE_DESCRIPTOR_SET_LAYOUT_SUPPORT);
    vn_encode_VkStructureType(enc, &(VkStructureType){ VK_STRUCTURE_TYPE_DESCRIPTOR_SET_LAYOUT_SUPPORT });
    vn_encode_VkDescriptorSetLayoutSupport_pnext_partial(enc, val->pNext);
    vn_encode_VkDescriptorSetLayoutSupport_self_partial(enc, val);
}

static inline size_t vn_sizeof_vkCreateDescriptorSetLayout(VkDevice device, const VkDescriptorSetLayoutCreateInfo* pCreateInfo, const VkAllocationCallbacks* pAllocator, VkDescriptorSetLayout* pSetLayout)
{
    const VkCommandTypeEXT cmd_type = VK_COMMAND_TYPE_vkCreateDescriptorSetLayout_EXT;
    const VkFlags cmd_flags = 0;
    size_t cmd_size = vn_sizeof_VkCommandTypeEXT(&cmd_type) + vn_sizeof_VkFlags(&cmd_flags);

    cmd_size += vn_sizeof_VkDevice(&device);
    cmd_size += vn_sizeof_simple_pointer(pCreateInfo);
    if (pCreateInfo)
        cmd_size += vn_sizeof_VkDescriptorSetLayoutCreateInfo(pCreateInfo);
    cmd_size += vn_sizeof_simple_pointer(pAllocator);
    if (pAllocator)
        assert(false);
    cmd_size += vn_sizeof_simple_pointer(pSetLayout);
    if (pSetLayout)
        cmd_size += vn_sizeof_VkDescriptorSetLayout(pSetLayout);

    return cmd_size;
}

static inline void vn_encode_vkCreateDescriptorSetLayout(struct vn_cs_encoder *enc, VkCommandFlagsEXT cmd_flags, VkDevice device, const VkDescriptorSetLayoutCreateInfo* pCreateInfo, const VkAllocationCallbacks* pAllocator, VkDescriptorSetLayout* pSetLayout)
{
    const VkCommandTypeEXT cmd_type = VK_COMMAND_TYPE_vkCreateDescriptorSetLayout_EXT;

    vn_encode_VkCommandTypeEXT(enc, &cmd_type);
    vn_encode_VkFlags(enc, &cmd_flags);

    vn_encode_VkDevice(enc, &device);
    if (vn_encode_simple_pointer(enc, pCreateInfo))
        vn_encode_VkDescriptorSetLayoutCreateInfo(enc, pCreateInfo);
    if (vn_encode_simple_pointer(enc, pAllocator))
        assert(false);
    if (vn_encode_simple_pointer(enc, pSetLayout))
        vn_encode_VkDescriptorSetLayout(enc, pSetLayout);
}

static inline size_t vn_sizeof_vkCreateDescriptorSetLayout_reply(VkDevice device, const VkDescriptorSetLayoutCreateInfo* pCreateInfo, const VkAllocationCallbacks* pAllocator, VkDescriptorSetLayout* pSetLayout)
{
    const VkCommandTypeEXT cmd_type = VK_COMMAND_TYPE_vkCreateDescriptorSetLayout_EXT;
    size_t cmd_size = vn_sizeof_VkCommandTypeEXT(&cmd_type);

    VkResult ret;
    cmd_size += vn_sizeof_VkResult(&ret);
    /* skip device */
    /* skip pCreateInfo */
    /* skip pAllocator */
    cmd_size += vn_sizeof_simple_pointer(pSetLayout);
    if (pSetLayout)
        cmd_size += vn_sizeof_VkDescriptorSetLayout(pSetLayout);

    return cmd_size;
}

static inline VkResult vn_decode_vkCreateDescriptorSetLayout_reply(struct vn_cs_decoder *dec, VkDevice device, const VkDescriptorSetLayoutCreateInfo* pCreateInfo, const VkAllocationCallbacks* pAllocator, VkDescriptorSetLayout* pSetLayout)
{
    VkCommandTypeEXT command_type;
    vn_decode_VkCommandTypeEXT(dec, &command_type);
    assert(command_type == VK_COMMAND_TYPE_vkCreateDescriptorSetLayout_EXT);

    VkResult ret;
    vn_decode_VkResult(dec, &ret);
    /* skip device */
    /* skip pCreateInfo */
    /* skip pAllocator */
    if (vn_decode_simple_pointer(dec)) {
        vn_decode_VkDescriptorSetLayout(dec, pSetLayout);
    } else {
        pSetLayout = NULL;
    }

    return ret;
}

static inline size_t vn_sizeof_vkDestroyDescriptorSetLayout(VkDevice device, VkDescriptorSetLayout descriptorSetLayout, const VkAllocationCallbacks* pAllocator)
{
    const VkCommandTypeEXT cmd_type = VK_COMMAND_TYPE_vkDestroyDescriptorSetLayout_EXT;
    const VkFlags cmd_flags = 0;
    size_t cmd_size = vn_sizeof_VkCommandTypeEXT(&cmd_type) + vn_sizeof_VkFlags(&cmd_flags);

    cmd_size += vn_sizeof_VkDevice(&device);
    cmd_size += vn_sizeof_VkDescriptorSetLayout(&descriptorSetLayout);
    cmd_size += vn_sizeof_simple_pointer(pAllocator);
    if (pAllocator)
        assert(false);

    return cmd_size;
}

static inline void vn_encode_vkDestroyDescriptorSetLayout(struct vn_cs_encoder *enc, VkCommandFlagsEXT cmd_flags, VkDevice device, VkDescriptorSetLayout descriptorSetLayout, const VkAllocationCallbacks* pAllocator)
{
    const VkCommandTypeEXT cmd_type = VK_COMMAND_TYPE_vkDestroyDescriptorSetLayout_EXT;

    vn_encode_VkCommandTypeEXT(enc, &cmd_type);
    vn_encode_VkFlags(enc, &cmd_flags);

    vn_encode_VkDevice(enc, &device);
    vn_encode_VkDescriptorSetLayout(enc, &descriptorSetLayout);
    if (vn_encode_simple_pointer(enc, pAllocator))
        assert(false);
}

static inline size_t vn_sizeof_vkDestroyDescriptorSetLayout_reply(VkDevice device, VkDescriptorSetLayout descriptorSetLayout, const VkAllocationCallbacks* pAllocator)
{
    const VkCommandTypeEXT cmd_type = VK_COMMAND_TYPE_vkDestroyDescriptorSetLayout_EXT;
    size_t cmd_size = vn_sizeof_VkCommandTypeEXT(&cmd_type);

    /* skip device */
    /* skip descriptorSetLayout */
    /* skip pAllocator */

    return cmd_size;
}

static inline void vn_decode_vkDestroyDescriptorSetLayout_reply(struct vn_cs_decoder *dec, VkDevice device, VkDescriptorSetLayout descriptorSetLayout, const VkAllocationCallbacks* pAllocator)
{
    VkCommandTypeEXT command_type;
    vn_decode_VkCommandTypeEXT(dec, &command_type);
    assert(command_type == VK_COMMAND_TYPE_vkDestroyDescriptorSetLayout_EXT);

    /* skip device */
    /* skip descriptorSetLayout */
    /* skip pAllocator */
}

static inline size_t vn_sizeof_vkGetDescriptorSetLayoutSupport(VkDevice device, const VkDescriptorSetLayoutCreateInfo* pCreateInfo, VkDescriptorSetLayoutSupport* pSupport)
{
    const VkCommandTypeEXT cmd_type = VK_COMMAND_TYPE_vkGetDescriptorSetLayoutSupport_EXT;
    const VkFlags cmd_flags = 0;
    size_t cmd_size = vn_sizeof_VkCommandTypeEXT(&cmd_type) + vn_sizeof_VkFlags(&cmd_flags);

    cmd_size += vn_sizeof_VkDevice(&device);
    cmd_size += vn_sizeof_simple_pointer(pCreateInfo);
    if (pCreateInfo)
        cmd_size += vn_sizeof_VkDescriptorSetLayoutCreateInfo(pCreateInfo);
    cmd_size += vn_sizeof_simple_pointer(pSupport);
    if (pSupport)
        cmd_size += vn_sizeof_VkDescriptorSetLayoutSupport_partial(pSupport);

    return cmd_size;
}

static inline void vn_encode_vkGetDescriptorSetLayoutSupport(struct vn_cs_encoder *enc, VkCommandFlagsEXT cmd_flags, VkDevice device, const VkDescriptorSetLayoutCreateInfo* pCreateInfo, VkDescriptorSetLayoutSupport* pSupport)
{
    const VkCommandTypeEXT cmd_type = VK_COMMAND_TYPE_vkGetDescriptorSetLayoutSupport_EXT;

    vn_encode_VkCommandTypeEXT(enc, &cmd_type);
    vn_encode_VkFlags(enc, &cmd_flags);

    vn_encode_VkDevice(enc, &device);
    if (vn_encode_simple_pointer(enc, pCreateInfo))
        vn_encode_VkDescriptorSetLayoutCreateInfo(enc, pCreateInfo);
    if (vn_encode_simple_pointer(enc, pSupport))
        vn_encode_VkDescriptorSetLayoutSupport_partial(enc, pSupport);
}

static inline size_t vn_sizeof_vkGetDescriptorSetLayoutSupport_reply(VkDevice device, const VkDescriptorSetLayoutCreateInfo* pCreateInfo, VkDescriptorSetLayoutSupport* pSupport)
{
    const VkCommandTypeEXT cmd_type = VK_COMMAND_TYPE_vkGetDescriptorSetLayoutSupport_EXT;
    size_t cmd_size = vn_sizeof_VkCommandTypeEXT(&cmd_type);

    /* skip device */
    /* skip pCreateInfo */
    cmd_size += vn_sizeof_simple_pointer(pSupport);
    if (pSupport)
        cmd_size += vn_sizeof_VkDescriptorSetLayoutSupport(pSupport);

    return cmd_size;
}

static inline void vn_decode_vkGetDescriptorSetLayoutSupport_reply(struct vn_cs_decoder *dec, VkDevice device, const VkDescriptorSetLayoutCreateInfo* pCreateInfo, VkDescriptorSetLayoutSupport* pSupport)
{
    VkCommandTypeEXT command_type;
    vn_decode_VkCommandTypeEXT(dec, &command_type);
    assert(command_type == VK_COMMAND_TYPE_vkGetDescriptorSetLayoutSupport_EXT);

    /* skip device */
    /* skip pCreateInfo */
    if (vn_decode_simple_pointer(dec)) {
        vn_decode_VkDescriptorSetLayoutSupport(dec, pSupport);
    } else {
        pSupport = NULL;
    }
}

static inline void vn_submit_vkCreateDescriptorSetLayout(struct vn_instance *vn_instance, VkCommandFlagsEXT cmd_flags, VkDevice device, const VkDescriptorSetLayoutCreateInfo* pCreateInfo, const VkAllocationCallbacks* pAllocator, VkDescriptorSetLayout* pSetLayout, struct vn_instance_submit_command *submit)
{
    uint8_t local_cmd_data[VN_SUBMIT_LOCAL_CMD_SIZE];
    void *cmd_data = local_cmd_data;
    size_t cmd_size = vn_sizeof_vkCreateDescriptorSetLayout(device, pCreateInfo, pAllocator, pSetLayout);
    if (cmd_size > sizeof(local_cmd_data)) {
        cmd_data = malloc(cmd_size);
        if (!cmd_data)
            cmd_size = 0;
    }
    const size_t reply_size = cmd_flags & VK_COMMAND_GENERATE_REPLY_BIT_EXT ? vn_sizeof_vkCreateDescriptorSetLayout_reply(device, pCreateInfo, pAllocator, pSetLayout) : 0;

    struct vn_cs_encoder *enc = vn_instance_submit_command_init(vn_instance, submit, cmd_data, cmd_size, reply_size);
    if (cmd_size) {
        vn_encode_vkCreateDescriptorSetLayout(enc, cmd_flags, device, pCreateInfo, pAllocator, pSetLayout);
        vn_instance_submit_command(vn_instance, submit);
        if (cmd_data != local_cmd_data)
            free(cmd_data);
    }
}

static inline void vn_submit_vkDestroyDescriptorSetLayout(struct vn_instance *vn_instance, VkCommandFlagsEXT cmd_flags, VkDevice device, VkDescriptorSetLayout descriptorSetLayout, const VkAllocationCallbacks* pAllocator, struct vn_instance_submit_command *submit)
{
    uint8_t local_cmd_data[VN_SUBMIT_LOCAL_CMD_SIZE];
    void *cmd_data = local_cmd_data;
    size_t cmd_size = vn_sizeof_vkDestroyDescriptorSetLayout(device, descriptorSetLayout, pAllocator);
    if (cmd_size > sizeof(local_cmd_data)) {
        cmd_data = malloc(cmd_size);
        if (!cmd_data)
            cmd_size = 0;
    }
    const size_t reply_size = cmd_flags & VK_COMMAND_GENERATE_REPLY_BIT_EXT ? vn_sizeof_vkDestroyDescriptorSetLayout_reply(device, descriptorSetLayout, pAllocator) : 0;

    struct vn_cs_encoder *enc = vn_instance_submit_command_init(vn_instance, submit, cmd_data, cmd_size, reply_size);
    if (cmd_size) {
        vn_encode_vkDestroyDescriptorSetLayout(enc, cmd_flags, device, descriptorSetLayout, pAllocator);
        vn_instance_submit_command(vn_instance, submit);
        if (cmd_data != local_cmd_data)
            free(cmd_data);
    }
}

static inline void vn_submit_vkGetDescriptorSetLayoutSupport(struct vn_instance *vn_instance, VkCommandFlagsEXT cmd_flags, VkDevice device, const VkDescriptorSetLayoutCreateInfo* pCreateInfo, VkDescriptorSetLayoutSupport* pSupport, struct vn_instance_submit_command *submit)
{
    uint8_t local_cmd_data[VN_SUBMIT_LOCAL_CMD_SIZE];
    void *cmd_data = local_cmd_data;
    size_t cmd_size = vn_sizeof_vkGetDescriptorSetLayoutSupport(device, pCreateInfo, pSupport);
    if (cmd_size > sizeof(local_cmd_data)) {
        cmd_data = malloc(cmd_size);
        if (!cmd_data)
            cmd_size = 0;
    }
    const size_t reply_size = cmd_flags & VK_COMMAND_GENERATE_REPLY_BIT_EXT ? vn_sizeof_vkGetDescriptorSetLayoutSupport_reply(device, pCreateInfo, pSupport) : 0;

    struct vn_cs_encoder *enc = vn_instance_submit_command_init(vn_instance, submit, cmd_data, cmd_size, reply_size);
    if (cmd_size) {
        vn_encode_vkGetDescriptorSetLayoutSupport(enc, cmd_flags, device, pCreateInfo, pSupport);
        vn_instance_submit_command(vn_instance, submit);
        if (cmd_data != local_cmd_data)
            free(cmd_data);
    }
}

static inline VkResult vn_call_vkCreateDescriptorSetLayout(struct vn_instance *vn_instance, VkDevice device, const VkDescriptorSetLayoutCreateInfo* pCreateInfo, const VkAllocationCallbacks* pAllocator, VkDescriptorSetLayout* pSetLayout)
{
    VN_TRACE_FUNC();

    struct vn_instance_submit_command submit;
    vn_submit_vkCreateDescriptorSetLayout(vn_instance, VK_COMMAND_GENERATE_REPLY_BIT_EXT, device, pCreateInfo, pAllocator, pSetLayout, &submit);
    struct vn_cs_decoder *dec = vn_instance_get_command_reply(vn_instance, &submit);
    if (dec) {
        const VkResult ret = vn_decode_vkCreateDescriptorSetLayout_reply(dec, device, pCreateInfo, pAllocator, pSetLayout);
        vn_instance_free_command_reply(vn_instance, &submit);
        return ret;
    } else {
        return VK_ERROR_OUT_OF_HOST_MEMORY;
    }
}

static inline void vn_async_vkCreateDescriptorSetLayout(struct vn_instance *vn_instance, VkDevice device, const VkDescriptorSetLayoutCreateInfo* pCreateInfo, const VkAllocationCallbacks* pAllocator, VkDescriptorSetLayout* pSetLayout)
{
    struct vn_instance_submit_command submit;
    vn_submit_vkCreateDescriptorSetLayout(vn_instance, 0, device, pCreateInfo, pAllocator, pSetLayout, &submit);
}

static inline void vn_call_vkDestroyDescriptorSetLayout(struct vn_instance *vn_instance, VkDevice device, VkDescriptorSetLayout descriptorSetLayout, const VkAllocationCallbacks* pAllocator)
{
    VN_TRACE_FUNC();

    struct vn_instance_submit_command submit;
    vn_submit_vkDestroyDescriptorSetLayout(vn_instance, VK_COMMAND_GENERATE_REPLY_BIT_EXT, device, descriptorSetLayout, pAllocator, &submit);
    struct vn_cs_decoder *dec = vn_instance_get_command_reply(vn_instance, &submit);
    if (dec) {
        vn_decode_vkDestroyDescriptorSetLayout_reply(dec, device, descriptorSetLayout, pAllocator);
        vn_instance_free_command_reply(vn_instance, &submit);
    }
}

static inline void vn_async_vkDestroyDescriptorSetLayout(struct vn_instance *vn_instance, VkDevice device, VkDescriptorSetLayout descriptorSetLayout, const VkAllocationCallbacks* pAllocator)
{
    struct vn_instance_submit_command submit;
    vn_submit_vkDestroyDescriptorSetLayout(vn_instance, 0, device, descriptorSetLayout, pAllocator, &submit);
}

static inline void vn_call_vkGetDescriptorSetLayoutSupport(struct vn_instance *vn_instance, VkDevice device, const VkDescriptorSetLayoutCreateInfo* pCreateInfo, VkDescriptorSetLayoutSupport* pSupport)
{
    VN_TRACE_FUNC();

    struct vn_instance_submit_command submit;
    vn_submit_vkGetDescriptorSetLayoutSupport(vn_instance, VK_COMMAND_GENERATE_REPLY_BIT_EXT, device, pCreateInfo, pSupport, &submit);
    struct vn_cs_decoder *dec = vn_instance_get_command_reply(vn_instance, &submit);
    if (dec) {
        vn_decode_vkGetDescriptorSetLayoutSupport_reply(dec, device, pCreateInfo, pSupport);
        vn_instance_free_command_reply(vn_instance, &submit);
    }
}

static inline void vn_async_vkGetDescriptorSetLayoutSupport(struct vn_instance *vn_instance, VkDevice device, const VkDescriptorSetLayoutCreateInfo* pCreateInfo, VkDescriptorSetLayoutSupport* pSupport)
{
    struct vn_instance_submit_command submit;
    vn_submit_vkGetDescriptorSetLayoutSupport(vn_instance, 0, device, pCreateInfo, pSupport, &submit);
}

#endif /* VN_PROTOCOL_DRIVER_DESCRIPTOR_SET_LAYOUT_H */
