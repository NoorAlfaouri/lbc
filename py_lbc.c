#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include "lbc.h"

/* Forward declare lbc CLI entry point */
int lbc_cli_main(int argc, char **argv);

static PyObject *py_lbc_compress(PyObject *self, PyObject *args, PyObject *kwargs) {
    (void)self;
    static char *kwlist[] = {"data", "chunk", NULL};
    Py_buffer view;
    unsigned long chunk = 8388608UL;

    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "y*|k", kwlist, &view, &chunk)) {
        return NULL;
    }

    void *out = NULL;
    size_t out_n = 0;
    lbc_status status;
    Py_BEGIN_ALLOW_THREADS
    status = lbc_compress(view.buf, view.len, chunk, &out, &out_n);
    Py_END_ALLOW_THREADS

    PyBuffer_Release(&view);

    if (status != LBC_OK) {
        if (out) lbc_free(out);
        PyErr_Format(PyExc_RuntimeError, "LBC compression failed: %s (code %d)",
                     lbc_status_string(status), (int)status);
        return NULL;
    }

    PyObject *result = PyBytes_FromStringAndSize((const char *)out, (Py_ssize_t)out_n);
    lbc_free(out);
    return result;
}

static PyObject *py_lbc_decompress(PyObject *self, PyObject *args) {
    (void)self;
    Py_buffer view;
    if (!PyArg_ParseTuple(args, "y*", &view)) {
        return NULL;
    }

    void *out = NULL;
    size_t out_n = 0;
    lbc_status status;
    Py_BEGIN_ALLOW_THREADS
    status = lbc_decompress(view.buf, view.len, &out, &out_n);
    Py_END_ALLOW_THREADS

    PyBuffer_Release(&view);

    if (status != LBC_OK) {
        if (out) lbc_free(out);
        PyErr_Format(PyExc_RuntimeError, "LBC decompression failed: %s (code %d)",
                     lbc_status_string(status), (int)status);
        return NULL;
    }

    PyObject *result = PyBytes_FromStringAndSize((const char *)out, (Py_ssize_t)out_n);
    lbc_free(out);
    return result;
}

static PyObject *py_lbc_compress_file(PyObject *self, PyObject *args, PyObject *kwargs) {
    (void)self;
    static char *kwlist[] = {"source", "destination", "chunk", NULL};
    const char *src = NULL;
    const char *dst = NULL;
    unsigned long chunk = 8388608UL;

    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "ss|k", kwlist, &src, &dst, &chunk)) {
        return NULL;
    }

    lbc_status status = lbc_compress_file(src, dst, chunk);
    if (status != LBC_OK) {
        PyErr_Format(PyExc_RuntimeError, "LBC file compression failed: %s (code %d)",
                     lbc_status_string(status), (int)status);
        return NULL;
    }
    Py_RETURN_NONE;
}

static PyObject *py_lbc_decompress_file(PyObject *self, PyObject *args) {
    (void)self;
    const char *src = NULL;
    const char *dst = NULL;

    if (!PyArg_ParseTuple(args, "ss", &src, &dst)) {
        return NULL;
    }

    lbc_status status = lbc_decompress_file(src, dst);
    if (status != LBC_OK) {
        PyErr_Format(PyExc_RuntimeError, "LBC file decompression failed: %s (code %d)",
                     lbc_status_string(status), (int)status);
        return NULL;
    }
    Py_RETURN_NONE;
}

static PyObject *py_lbc_cli(PyObject *self, PyObject *args) {
    (void)self;
    PyObject *py_argv = NULL;
    if (!PyArg_ParseTuple(args, "O!", &PyList_Type, &py_argv)) {
        return NULL;
    }

    Py_ssize_t argc = PyList_Size(py_argv);
    char **argv = (char **)malloc(((size_t)argc + 1) * sizeof(char *));
    if (!argv) {
        return PyErr_NoMemory();
    }

    for (Py_ssize_t i = 0; i < argc; ++i) {
        PyObject *item = PyList_GetItem(py_argv, i);
        if (!PyUnicode_Check(item)) {
            free(argv);
            PyErr_SetString(PyExc_TypeError, "argv items must be strings");
            return NULL;
        }
        argv[i] = (char *)PyUnicode_AsUTF8(item);
    }
    argv[argc] = NULL;

    int ret = lbc_cli_main((int)argc, argv);
    free(argv);
    return PyLong_FromLong(ret);
}

static PyMethodDef LbcMethods[] = {
    {"compress", (PyCFunction)py_lbc_compress, METH_VARARGS | METH_KEYWORDS, "Compress bytes using LBC."},
    {"decompress", (PyCFunction)py_lbc_decompress, METH_VARARGS, "Decompress LBC archive bytes."},
    {"compress_file", (PyCFunction)py_lbc_compress_file, METH_VARARGS | METH_KEYWORDS, "Compress a file to an LBC archive."},
    {"decompress_file", (PyCFunction)py_lbc_decompress_file, METH_VARARGS, "Decompress an LBC archive to a file."},
    {"cli", (PyCFunction)py_lbc_cli, METH_VARARGS, "Run the LBC command-line interface with a list of string arguments."},
    {NULL, NULL, 0, NULL}
};

static struct PyModuleDef lbcmodule = {
    PyModuleDef_HEAD_INIT,
    "_clbc",
    "Lossless Block Codec (LBC) ultra high-ratio compression engine",
    -1,
    LbcMethods
};

PyMODINIT_FUNC PyInit__clbc(void) {
    return PyModule_Create(&lbcmodule);
}
